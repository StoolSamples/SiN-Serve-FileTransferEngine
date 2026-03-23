"""
tests/test_stream_manager.py — Unit tests for StreamManager (Phase 3).

Test 5 performs a full UDP loopback using real sockets:
  • Two StreamManager streams send NUM_CHUNKS chunks of CHUNK_SIZE bytes.
  • Two background receiver threads collect all incoming DATA packets.
  • After the pass, the total received-chunk count must equal NUM_CHUNKS.

Ports: 19300–19301 (chosen to avoid conflicts with production ports).
"""

import os
import queue
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

# ── Ensure project root is on sys.path ───────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from config import Config
from crypto import CryptoEngine
from pacing import AdaptivePacingController
from protocol import parse_packet, PacketType
from stream_manager import ScalingDecision, ScalingHook, StreamManager, StreamStats
from transport import UDPTransport


# ── Constants for test 5 ──────────────────────────────────────────────────────

_CHUNK_SIZE  = 512
_NUM_CHUNKS  = 10
_BASE_PORT   = 19300   # streams use 19300 and 19301
_NUM_STREAMS = 2
_SESSION_ID  = b"\xab" * 16


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_config(chunk_size: int = _CHUNK_SIZE, num_streams: int = _NUM_STREAMS) -> Config:
    """Return a default Config with the given chunk_size."""
    cfg = Config.__new__(Config)
    # Manually populate _data so we don't need config.json on disk
    from config import DEFAULT_CONFIG
    import copy
    cfg._data = copy.deepcopy(DEFAULT_CONFIG)
    cfg._data["transfer"]["chunk_size"] = chunk_size
    cfg._data["transfer"]["num_streams"] = num_streams
    return cfg


def _make_pacing(config: Config) -> AdaptivePacingController:
    return AdaptivePacingController(
        num_streams=config.num_streams,
        chunk_size=config.chunk_size,
    )


def _make_sender_transports(num: int) -> list:
    """Create ephemeral-port sender UDPTransports (port 0 = OS-assigned)."""
    return [UDPTransport(bind_addr=("", 0), buffer_size=1 << 20) for _ in range(num)]


def _make_crypto(enabled: bool = False) -> CryptoEngine:
    return CryptoEngine(enabled=enabled)


# ── Test 1 — importability ────────────────────────────────────────────────────

def test_import():
    """StreamManager and ScalingDecision are importable from stream_manager."""
    from stream_manager import StreamManager, ScalingDecision
    assert StreamManager is not None
    assert ScalingDecision is not None


# ── Test 2 — construction / basic properties ──────────────────────────────────

def test_stream_manager_init():
    """num_streams==2, live_sent has 2 elements, loss_rate==0.0 after construction."""
    cfg        = _make_config(num_streams=2)
    pacing     = _make_pacing(cfg)
    transports = _make_sender_transports(2)
    crypto     = _make_crypto()

    sm = StreamManager(
        config=cfg,
        pacing=pacing,
        data_transports=transports,
        dest_host="127.0.0.1",
        data_base_port=_BASE_PORT,
        filepath=__file__,     # any existing file; won't be read in this test
        session_id=_SESSION_ID,
        crypto=crypto,
    )

    assert sm.num_streams == 2
    assert len(sm.live_sent) == 2
    assert sm.loss_rate == 0.0

    for t in transports:
        t.close()


# ── Test 3 — hook registration ────────────────────────────────────────────────

def test_scaling_hook_registration():
    """set_scaling_hook stores hook and interval without raising."""
    cfg        = _make_config()
    pacing     = _make_pacing(cfg)
    transports = _make_sender_transports(2)
    crypto     = _make_crypto()

    sm = StreamManager(
        config=cfg,
        pacing=pacing,
        data_transports=transports,
        dest_host="127.0.0.1",
        data_base_port=_BASE_PORT,
        filepath=__file__,
        session_id=_SESSION_ID,
        crypto=crypto,
    )

    def my_hook(manager: StreamManager) -> ScalingDecision:
        return ScalingDecision(requested_streams=4, reason="test hook")

    sm.set_scaling_hook(my_hook, probe_interval_s=10.0)

    assert sm._hook is my_hook
    assert sm._probe_interval_s == 10.0

    for t in transports:
        t.close()


# ── Test 4 — ScalingDecision defaults ────────────────────────────────────────

def test_scaling_decision_no_change():
    """Default ScalingDecision has requested_streams=None and reason=''."""
    d = ScalingDecision()
    assert d.requested_streams is None
    assert d.reason == ""


# ── Test 5 — full loopback ────────────────────────────────────────────────────

def test_stream_manager_enqueue_and_receive(tmp_path):
    """
    Full UDP loopback test.

    1. Create a real file with NUM_CHUNKS * CHUNK_SIZE bytes of known data.
    2. Bind real receiver sockets on 19300 and 19301.
    3. Start receiver threads that count distinct chunk_ids received.
    4. StreamManager sends all chunks via enqueue_pass().
    5. After the pass, total received chunk count == NUM_CHUNKS.
    """
    # ── Build test file ───────────────────────────────────────────────────────
    file_path = tmp_path / "test_payload.bin"
    file_data = bytes(range(256)) * (_CHUNK_SIZE // 256 + 1)  # repeating pattern
    # Write exactly NUM_CHUNKS * CHUNK_SIZE bytes
    total_bytes = _NUM_CHUNKS * _CHUNK_SIZE
    file_path.write_bytes((file_data * (total_bytes // len(file_data) + 1))[:total_bytes])

    # ── Bind receiver sockets ─────────────────────────────────────────────────
    recv_socks = []
    for i in range(_NUM_STREAMS):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        s.bind(("127.0.0.1", _BASE_PORT + i))
        s.settimeout(2.0)
        recv_socks.append(s)

    received_ids: set = set()
    recv_lock = threading.Lock()

    def receiver_thread(sock: socket.socket, expected_total: int):
        """Collect chunk_ids until we have expected_total or timeout."""
        from protocol import parse_packet, PacketType, parse_data_payload
        while True:
            try:
                data, _ = sock.recvfrom(65535)
            except socket.timeout:
                # Check if we are done
                with recv_lock:
                    if len(received_ids) >= expected_total:
                        break
                # Short timeout: try once more then bail
                break
            except OSError:
                break

            pkt = parse_packet(data)
            if pkt is None or pkt.ptype != PacketType.DATA:
                continue
            try:
                info = parse_data_payload(pkt.payload)
                with recv_lock:
                    received_ids.add(info["chunk_id"])
                    if len(received_ids) >= expected_total:
                        break
            except Exception:
                pass

    recv_threads = []
    for sock in recv_socks:
        t = threading.Thread(
            target=receiver_thread,
            args=(sock, _NUM_CHUNKS),
            daemon=True,
        )
        t.start()
        recv_threads.append(t)

    # ── Build StreamManager ───────────────────────────────────────────────────
    cfg    = _make_config(chunk_size=_CHUNK_SIZE, num_streams=_NUM_STREAMS)
    pacing = _make_pacing(cfg)
    crypto = _make_crypto(enabled=False)

    sender_transports = _make_sender_transports(_NUM_STREAMS)

    sm = StreamManager(
        config=cfg,
        pacing=pacing,
        data_transports=sender_transports,
        dest_host="127.0.0.1",
        data_base_port=_BASE_PORT,
        filepath=str(file_path),
        session_id=_SESSION_ID,
        crypto=crypto,
    )

    sm.start()

    chunk_ids = list(range(_NUM_CHUNKS))
    sm.enqueue_pass(chunk_ids, label="TestPass")

    final_stats = sm.stop()

    # ── Wait for receivers ────────────────────────────────────────────────────
    for t in recv_threads:
        t.join(timeout=5.0)

    # ── Cleanup ───────────────────────────────────────────────────────────────
    for sock in recv_socks:
        sock.close()
    for t in sender_transports:
        t.close()

    # ── Assertions ───────────────────────────────────────────────────────────
    with recv_lock:
        n_received = len(received_ids)

    total_sent = sum(s.sent for s in final_stats)

    assert total_sent == _NUM_CHUNKS, (
        f"Expected {_NUM_CHUNKS} sent, got {total_sent}"
    )
    assert n_received == _NUM_CHUNKS, (
        f"Expected {_NUM_CHUNKS} received chunk IDs, got {n_received}  "
        f"received={sorted(received_ids)}"
    )
