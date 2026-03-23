"""
protocol.py — Packet type definitions and binary serialization/deserialization.

Channel assignment (Phase 4):
  Port base+0 (9000) — Control  : INIT, META, ACK, FINISH, COMPLETE, ERROR, RATE_HINT(sender→recv)
  Port base+1 (9001) — Feedback : NACK, THROUGHPUT_REPORT, RATE_HINT(recv→sender), RESEND
  Port base+2..+5    — Data     : DATA (4 streams)

Header layout (25 bytes):
  [0]      packet_type  : uint8
  [1:17]   session_id   : 16 bytes
  [17:21]  seq_num      : uint32
  [21:25]  payload_len  : uint32
"""

import struct
from dataclasses import dataclass
from enum import IntEnum
from typing import List, Optional


class PacketType(IntEnum):
    INIT              = 0x01
    META              = 0x02
    DATA              = 0x03
    ACK               = 0x04
    RESEND            = 0x05   # Phase 4: moved to feedback channel 9001
    FINISH            = 0x06
    COMPLETE          = 0x07
    ERROR             = 0x08
    NACK              = 0x09   # Phase 4: per-chunk SHA-256 failure, receiver→sender on 9001
    THROUGHPUT_REPORT = 0x0A   # Phase 4: delivery rate report, receiver→sender on 9001 every 500ms
    RATE_HINT         = 0x0B   # Phase 4: max rate advisory, exchanged at handshake start
    LOSS_REPORT       = 0x0C   # sender→receiver on control channel: per-pass ramp diagnostics


_HDR_FMT  = "!B16sII"
HEADER_SIZE = struct.calcsize(_HDR_FMT)  # 25 bytes

_INIT_FMT         = "!HB"
_INIT_SIZE        = struct.calcsize(_INIT_FMT)

_META_FIXED_FMT   = "!HQII32s"
_META_FIXED_SIZE  = struct.calcsize(_META_FIXED_FMT)

_DATA_META_FMT    = "!IQI32s"
_DATA_META_SIZE   = struct.calcsize(_DATA_META_FMT)

_FINISH_FMT       = "!I32s"
_FINISH_SIZE      = struct.calcsize(_FINISH_FMT)

# Phase 4 payload formats
_NACK_FMT                = "!I"       # chunk_id(4)
_NACK_SIZE               = struct.calcsize(_NACK_FMT)

_THROUGHPUT_REPORT_FMT   = "!QIQII"  # bytes_window(8)+window_ms(4)+bytes_total(8)+elapsed_ms(4)+chunks_total(4)
_THROUGHPUT_REPORT_SIZE  = struct.calcsize(_THROUGHPUT_REPORT_FMT)

_RATE_HINT_FMT           = "!f"       # max_rate_mbps as float32
_RATE_HINT_SIZE          = struct.calcsize(_RATE_HINT_FMT)

_LOSS_REPORT_FMT         = "!HIIfBf"  # pass_index(2)+chunks_sent(4)+chunks_lost(4)+current_mbps(4)+tier(1)+pass_duration_sec(4) = 19 bytes
_LOSS_REPORT_SIZE        = struct.calcsize(_LOSS_REPORT_FMT)

MAX_CHUNK_SIZE = 65_434


@dataclass(slots=True)
class Packet:
    ptype:      PacketType
    session_id: bytes
    seq_num:    int
    payload:    bytes


def build_packet(ptype, session_id, seq_num, payload=b""):
    header = struct.pack(_HDR_FMT, int(ptype), session_id, seq_num, len(payload))
    return header + payload


def parse_packet(data: bytes) -> Optional[Packet]:
    if len(data) < HEADER_SIZE:
        return None
    try:
        ptype_raw, session_id, seq_num, payload_len = struct.unpack_from(_HDR_FMT, data)
        ptype = PacketType(ptype_raw)
    except (struct.error, ValueError):
        return None
    payload = data[HEADER_SIZE: HEADER_SIZE + payload_len]
    if len(payload) < payload_len:
        return None
    return Packet(ptype=ptype, session_id=session_id, seq_num=seq_num, payload=payload)


# ─── INIT ─────────────────────────────────────────────────────────────────────

def build_init_payload(version: int = 1, num_streams: int = 1,
                       mac_key: str = "") -> bytes:
    """
    Build an INIT payload.

    Layout:
      [0:2]  version       uint16
      [2]    num_streams   uint8
      [3:35] mac_key       32 ASCII bytes (omitted when mac_key is empty)

    The mac_key field is optional for backward compatibility — receivers that
    do not know about it simply ignore the extra bytes.
    """
    base = struct.pack(_INIT_FMT, version, num_streams)
    if mac_key:
        base += mac_key.encode("ascii")
    return base

def parse_init_payload(payload: bytes) -> dict:
    if len(payload) < 2:
        return {"version": 1, "num_streams": 1, "sender_mac_key": ""}
    version = struct.unpack_from("!H", payload)[0]
    num_streams = 1
    if len(payload) >= _INIT_SIZE:
        num_streams = struct.unpack_from("!B", payload, 2)[0]
    sender_mac_key = ""
    if len(payload) >= _INIT_SIZE + 32:
        try:
            sender_mac_key = payload[_INIT_SIZE: _INIT_SIZE + 32].decode("ascii")
        except (UnicodeDecodeError, ValueError):
            sender_mac_key = ""
    return {
        "version":        version,
        "num_streams":    max(1, num_streams),
        "sender_mac_key": sender_mac_key,
    }


# ─── META ─────────────────────────────────────────────────────────────────────

def build_meta_payload(filename, file_size, total_chunks, chunk_size, file_sha256):
    fname_bytes = filename.encode("utf-8")
    fixed = struct.pack(_META_FIXED_FMT, len(fname_bytes), file_size, total_chunks, chunk_size, file_sha256)
    return fixed + fname_bytes

def parse_meta_payload(payload: bytes) -> dict:
    if len(payload) < _META_FIXED_SIZE:
        raise ValueError("META payload too short")
    fname_len, file_size, total_chunks, chunk_size, file_sha256 = struct.unpack_from(_META_FIXED_FMT, payload)
    name_end = _META_FIXED_SIZE + fname_len
    if len(payload) < name_end:
        raise ValueError("META payload: filename truncated")
    filename = payload[_META_FIXED_SIZE:name_end].decode("utf-8")
    return {"filename": filename, "file_size": file_size, "total_chunks": total_chunks,
            "chunk_size": chunk_size, "file_sha256": file_sha256}


# ─── DATA ─────────────────────────────────────────────────────────────────────

def build_data_payload(chunk_id, byte_offset, chunk_data_size, checksum, data):
    meta = struct.pack(_DATA_META_FMT, chunk_id, byte_offset, chunk_data_size, checksum)
    return meta + data

def parse_data_payload(payload: bytes) -> dict:
    if len(payload) < _DATA_META_SIZE:
        raise ValueError("DATA payload too short")
    chunk_id, byte_offset, chunk_data_size, checksum = struct.unpack_from(_DATA_META_FMT, payload)
    data_start = _DATA_META_SIZE
    data_end   = data_start + chunk_data_size
    if len(payload) < data_end:
        raise ValueError(f"DATA payload: expected {chunk_data_size} bytes, got {len(payload)-data_start}")
    return {"chunk_id": chunk_id, "byte_offset": byte_offset,
            "chunk_data_size": chunk_data_size, "checksum": checksum,
            "data": payload[data_start:data_end]}


# ─── ACK ─────────────────────────────────────────────────────────────────────

def build_ack_payload(ack_type: PacketType) -> bytes:
    return struct.pack("!B", int(ack_type))

def parse_ack_payload(payload: bytes) -> PacketType:
    if not payload:
        raise ValueError("ACK payload empty")
    return PacketType(struct.unpack_from("!B", payload)[0])


# ─── RESEND ───────────────────────────────────────────────────────────────────

def build_resend_payload(chunk_ids: List[int]) -> bytes:
    buf = struct.pack("!I", len(chunk_ids))
    if chunk_ids:
        buf += struct.pack(f"!{len(chunk_ids)}I", *chunk_ids)
    return buf

def parse_resend_payload(payload: bytes) -> List[int]:
    if len(payload) < 4:
        raise ValueError("RESEND payload too short")
    (count,) = struct.unpack_from("!I", payload)
    if len(payload) < 4 + count * 4:
        raise ValueError(f"RESEND payload: expected {count} IDs, too short")
    return list(struct.unpack_from(f"!{count}I", payload, 4))


# ─── FINISH ───────────────────────────────────────────────────────────────────

def build_finish_payload(total_chunks, file_sha256):
    return struct.pack(_FINISH_FMT, total_chunks, file_sha256)

def parse_finish_payload(payload: bytes) -> dict:
    if len(payload) < _FINISH_SIZE:
        raise ValueError("FINISH payload too short")
    total_chunks, file_sha256 = struct.unpack_from(_FINISH_FMT, payload)
    return {"total_chunks": total_chunks, "file_sha256": file_sha256}


# ─── COMPLETE ─────────────────────────────────────────────────────────────────

def build_complete_payload(status: int = 0) -> bytes:
    return struct.pack("!B", status)

def parse_complete_payload(payload: bytes) -> int:
    if not payload:
        return 0
    return struct.unpack_from("!B", payload)[0]


# ─── ERROR ────────────────────────────────────────────────────────────────────

def build_error_payload(code: int, message: str) -> bytes:
    return struct.pack("!H", code) + message.encode("utf-8")

def parse_error_payload(payload: bytes) -> dict:
    if len(payload) < 2:
        return {"code": 0, "message": ""}
    (code,) = struct.unpack_from("!H", payload)
    return {"code": code, "message": payload[2:].decode("utf-8", errors="replace")}


# ─── NACK ─────────────────────────────────────────────────────────────────────

def build_nack_payload(chunk_id: int) -> bytes:
    """Sent by receiver on feedback channel 9001 when a chunk fails SHA-256."""
    return struct.pack(_NACK_FMT, chunk_id)

def parse_nack_payload(payload: bytes) -> int:
    if len(payload) < _NACK_SIZE:
        raise ValueError("NACK payload too short")
    (chunk_id,) = struct.unpack_from(_NACK_FMT, payload)
    return chunk_id


# ─── THROUGHPUT_REPORT ────────────────────────────────────────────────────────

def build_throughput_report_payload(
    bytes_window: int,  # bytes written in this 500ms window
    window_ms:    int,  # actual window duration ms
    bytes_total:  int,  # cumulative bytes written since start
    elapsed_ms:   int,  # total ms since transfer start
    chunks_total: int,  # total chunks written
) -> bytes:
    """
    Sent by receiver on 9001 every 500ms.
    Sender derives: stable_mbps = bytes_window / window_ms * 1000 / 1_048_576
    """
    return struct.pack(_THROUGHPUT_REPORT_FMT, bytes_window, window_ms,
                       bytes_total, elapsed_ms, chunks_total)

def parse_throughput_report_payload(payload: bytes) -> dict:
    if len(payload) < _THROUGHPUT_REPORT_SIZE:
        raise ValueError("THROUGHPUT_REPORT payload too short")
    bw, wms, bt, ems, ct = struct.unpack_from(_THROUGHPUT_REPORT_FMT, payload)
    return {"bytes_window": bw, "window_ms": wms,
            "bytes_total": bt, "elapsed_ms": ems, "chunks_total": ct}


# ─── RATE_HINT ────────────────────────────────────────────────────────────────

def build_rate_hint_payload(max_rate_mbps: float) -> bytes:
    """
    0.0 = no configured limit.
    Sender → receiver on 9000: advisory for future receiver use.
    Receiver → sender on 9001: sender caps target_mbps at this value when > 0.
    """
    return struct.pack(_RATE_HINT_FMT, float(max_rate_mbps))

def parse_rate_hint_payload(payload: bytes) -> float:
    if len(payload) < _RATE_HINT_SIZE:
        return 0.0
    (rate,) = struct.unpack_from(_RATE_HINT_FMT, payload)
    return float(rate)


# ─── LOSS_REPORT ──────────────────────────────────────────────────────────────

def build_loss_report_payload(
    pass_index:        int,
    chunks_sent:       int,
    chunks_lost:       int,
    current_mbps:      float,
    tier:              int,
    pass_duration_sec: float,
) -> bytes:
    """
    Sent by sender on control channel (9000) after each FINISH/RESEND cycle.

    Fields:
        pass_index        uint16  — 0 = initial pass, 1+ = resend passes
        chunks_sent       uint32  — chunks dispatched in this pass
        chunks_lost       uint32  — chunks that needed resending (0 for final pass)
        current_mbps      float32 — sender's target_mbps at pass boundary
        tier              uint8   — ramp tier (0-3) selected at session start
        pass_duration_sec float32 — wall-clock seconds for this pass
    """
    return struct.pack(
        _LOSS_REPORT_FMT,
        pass_index, chunks_sent, chunks_lost,
        float(current_mbps), tier, float(pass_duration_sec),
    )


def parse_loss_report_payload(payload: bytes) -> dict:
    if len(payload) < _LOSS_REPORT_SIZE:
        raise ValueError("LOSS_REPORT payload too short")
    pass_index, chunks_sent, chunks_lost, current_mbps, tier, pass_duration_sec = \
        struct.unpack_from(_LOSS_REPORT_FMT, payload)
    return {
        "pass_index":        pass_index,
        "chunks_sent":       chunks_sent,
        "chunks_lost":       chunks_lost,
        "current_mbps":      float(current_mbps),
        "tier":              tier,
        "pass_duration_sec": float(pass_duration_sec),
    }
