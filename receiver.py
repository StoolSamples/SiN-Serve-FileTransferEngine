"""
receiver.py — FileReceiver: multi-stream UDP file receiver.

Phase 4 + RAM-buffer additions:

RAM-buffer mode (allow_ram_loading=True, file fits in available RAM):
  - Pre-allocates a bytearray the size of the file.
  - Data receiver threads write chunks directly into the buffer at byte_offset.
  - No write queue, no writer threads, no claimed/written divergence.
  - FINISH audit is instantaneous — checks the received-chunk bitmask directly.
  - When all chunks confirmed: one sequential write to disk, SHA-256 from buffer.
  - vCPU freed from write-queue management absorbs more incoming packets.

Disk mode (fallback when file does not fit in RAM):
  - Write queue drained before every FINISH audit, eliminating the overcount
    where in-flight chunks are mistakenly listed as missing.

RATE_HINT feedback:
  - _throughput_report_thread tracks a rolling window of measured rates.
  - After 5 clean windows, sends RATE_HINT to sender capping it at the
    receiver's actual sustained absorption rate.

Port layout (base_port=9000):
  9000 — Control  : INIT, META, ACK, FINISH, COMPLETE, ERROR
  9001 — Feedback : NACK, THROUGHPUT_REPORT, RATE_HINT, RESEND
  9002–9005 — Data: 4 streams

Peer-DB / adaptive ramp (per-peer pacing memory):
  sender_mac_key is extracted from the INIT payload (bytes 3–34) in
  _wait_for_init().  The receiver's own local_mac_key is appended to the
  INIT ACK so the sender can look up this node in its DB on the next send.
  write_result() is called at all transfer exit points so the receiver
  accumulates recv-direction history for use when it later becomes the sender.
"""

import hashlib
import json
import logging
import os
import queue
import threading
import time
from typing import Dict, List, Optional, Set, Tuple

import psutil

import peer_db
from config import Config
from crypto import CryptoEngine, NONCE_LENGTH
from integrity import compute_file_sha256, format_hex, verify_chunk_hash
from protocol import (
    PacketType, build_packet, parse_packet,
    build_ack_payload, build_resend_payload, build_complete_payload,
    build_error_payload, build_nack_payload, build_throughput_report_payload,
    build_rate_hint_payload, build_sack_payload, build_ping_payload,
    parse_rate_hint_payload,
    parse_init_payload, parse_meta_payload, parse_data_payload,
    parse_loss_report_payload, parse_ping_payload,
)
from transport import UDPTransport

logger = logging.getLogger(__name__)

_MAX_IDS_PER_RESEND  = 8_000
_WRITE_QUEUE_MAX     = 16_384
_NUM_WRITERS         = 2
_SHA_BLOCK           = 32 * 1024 * 1024   # 32 MiB


# ─── Sidecar (Phase 3, unchanged) ────────────────────────────────────────────

class SidecarManager:
    SIDECAR_SUFFIX = ".ft_progress"

    def __init__(self, output_path: str, metadata: dict) -> None:
        self._path     = output_path + self.SIDECAR_SUFFIX
        self._tmp_path = self._path + ".tmp"
        self._meta     = metadata
        self._lock     = threading.Lock()
        self._enabled  = True

    @classmethod
    def sidecar_path(cls, output_path: str) -> str:
        return output_path + cls.SIDECAR_SUFFIX

    @classmethod
    def load(cls, output_path: str) -> Optional[dict]:
        path = cls.sidecar_path(output_path)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return data if isinstance(data, dict) else None
        except FileNotFoundError:
            return None
        except (json.JSONDecodeError, OSError, ValueError) as exc:
            logger.warning("Sidecar load failed (%s): %s", path, exc)
            return None

    def flush_snapshot(self, written_chunks_snapshot: Set[int]) -> None:
        if not self._enabled:
            return
        payload = {**self._meta, "written_chunks": sorted(written_chunks_snapshot),
                   "timestamp": time.time()}
        with self._lock:
            try:
                with open(self._tmp_path, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh, separators=(",", ":"))
                os.replace(self._tmp_path, self._path)
            except OSError as exc:
                logger.warning("Sidecar flush failed: %s", exc)

    def delete(self) -> None:
        self._enabled = False
        for path in (self._path, self._tmp_path):
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
            except OSError as exc:
                logger.warning("Sidecar delete failed (%s): %s", path, exc)


# ─── FileReceiver ─────────────────────────────────────────────────────────────

class FileReceiver:

    _blackout_lock: threading.Lock = threading.Lock()
    _blackout: Dict[str, float]    = {}

    def __init__(self, config: Config) -> None:
        self._cfg    = config
        self._crypto = CryptoEngine(enabled=config.crypto_enabled)

    # ── Public entry point ────────────────────────────────────────────────────

    def receive_file(self, output_dir: str, bind_port: int,
                     local_mac_key: str = "") -> str:
        os.makedirs(output_dir, exist_ok=True)
        feedback_port = bind_port + 1
        data_base     = bind_port + 2

        logger.info("=" * 60)
        logger.info("FileReceiver  [Phase 4 + RAM buffer]")
        logger.info("  Control port   : %d", bind_port)
        logger.info("  Feedback port  : %d (sender listens)", feedback_port)
        logger.info("  Data ports     : %d–%d", data_base, data_base + self._cfg.num_streams - 1)
        logger.info("  Output dir     : %s", output_dir)
        logger.info("=" * 60)

        with UDPTransport(("", bind_port), buffer_size=self._cfg.socket_buffer_size) as ctrl:
            return self._run_receive(ctrl, output_dir, bind_port, feedback_port,
                                     data_base, local_mac_key)

    # ── RAM mode eligibility check ─────────────────────────────────────────────

    def _check_ram_mode(self, file_size: int) -> Tuple[bool, Optional[bytearray]]:
        """
        Returns (use_ram, buffer_or_None).

        Allocates a bytearray(file_size) only when:
          - allow_ram_loading is True in config
          - available RAM minus ram_amount_reserved_gb >= file_size
        Falls back to disk mode on any failure.
        """
        if not self._cfg.allow_ram_loading:
            logger.info("RAM mode: disabled in config — using disk mode")
            return False, None

        try:
            available_b  = psutil.virtual_memory().available
            reserved_b   = int(self._cfg.ram_amount_reserved_gb * 1024 ** 3)
            usable_b     = available_b - reserved_b

            avail_mb  = available_b / 1_048_576
            usable_mb = usable_b    / 1_048_576
            file_mb   = file_size   / 1_048_576

            if usable_b < file_size:
                logger.info(
                    "RAM mode: file=%.1f MB  available=%.1f MB  "
                    "reserved=%.2f GB  usable=%.1f MB — insufficient, "
                    "using disk mode",
                    file_mb, avail_mb,
                    self._cfg.ram_amount_reserved_gb, usable_mb,
                )
                return False, None

            logger.info(
                "RAM mode: allocating %.1f MB buffer  "
                "(available=%.1f MB  reserved=%.2f GB  usable=%.1f MB)",
                file_mb, avail_mb,
                self._cfg.ram_amount_reserved_gb, usable_mb,
            )
            buf = bytearray(file_size)
            logger.info("RAM buffer allocated (%.1f MB)", file_mb)
            return True, buf

        except Exception as exc:
            logger.warning("RAM mode check failed: %s — using disk mode", exc)
            return False, None

    # ── Main receive orchestration ─────────────────────────────────────────────

    def _run_receive(
        self, ctrl, output_dir, bind_port, feedback_port, data_base,
        local_mac_key: str = "",
    ) -> str:
        recv_timeout = self._cfg.recv_timeout
        num_streams  = self._cfg.num_streams

        session_id, sender_addr, num_streams, sender_mac_key = self._wait_for_init(
            ctrl, recv_timeout
        )
        feedback_dest = (sender_addr[0], feedback_port)

        if sender_mac_key:
            peer_db.upsert_peer(sender_mac_key)
            logger.info("Peer identified  sender_key=%s…", sender_mac_key[:8])

        feedback_transport = UDPTransport(("", 0), buffer_size=self._cfg.socket_buffer_size)
        try:
            data_transports = self._open_data_sockets(data_base, num_streams)
            try:
                # ACK INIT — extended payload carries the receiver's mac_key so
                # the sender can look this node up in its peer DB on the next send.
                # Layout: [0] ack_type  [1:33] local_mac_key (32 ASCII bytes)
                # Backward compatible — old senders ignore bytes after byte 0.
                _init_ack_payload = build_ack_payload(PacketType.INIT)
                if local_mac_key:
                    _init_ack_payload += local_mac_key.encode("ascii")
                ctrl.send(
                    build_packet(PacketType.ACK, session_id, 0, _init_ack_payload),
                    sender_addr,
                )
                logger.info(
                    "INIT ACK → %s:%d  (streams=%d  data %d–%d  feedback→%d)",
                    sender_addr[0], sender_addr[1], num_streams,
                    data_base, data_base + num_streams - 1, feedback_port,
                )

                meta         = self._wait_for_meta(ctrl, session_id, sender_addr, recv_timeout)
                filename     = meta["filename"]
                file_size    = meta["file_size"]
                total_chunks = meta["total_chunks"]
                chunk_size   = meta["chunk_size"]
                expected_sha = meta["file_sha256"]

                logger.info(
                    "META: file=%r  size=%d bytes  chunks=%d  chunk_size=%d",
                    filename, file_size, total_chunks, chunk_size,
                )

                output_path = os.path.join(output_dir, filename)

                # ── Decide RAM vs disk mode ────────────────────────────────────
                use_ram, ram_buffer = self._check_ram_mode(file_size)

                if not use_ram:
                    # Disk mode: pre-allocate file on disk
                    initial_written = self._load_resume_state(output_path, meta, session_id)
                    if (initial_written and os.path.isfile(output_path)
                            and os.path.getsize(output_path) == file_size):
                        logger.info(
                            "RESUME: %d/%d chunks already written",
                            len(initial_written), total_chunks,
                        )
                    else:
                        if initial_written:
                            logger.warning("RESUME: output missing/wrong size — starting fresh")
                            initial_written = set()
                        self._preallocate_file(output_path, file_size)
                else:
                    initial_written = set()

                # ACK META — extended payload: [ACK_TYPE, flags]
                # bit 0 of flags = hash_requested (receiver asks sender to hash)
                # Sender reads byte 0 for ACK type; byte 1 carries our preference.
                # Backward compatible: senders that don't know about byte 1 ignore it.
                _flags = 0x01 if self._cfg.hash_requested else 0x00
                _meta_ack_payload = bytes([int(PacketType.META), _flags])
                ctrl.send(
                    build_packet(PacketType.ACK, session_id, 0, _meta_ack_payload),
                    sender_addr,
                )
                logger.info(
                    "META ACK sent  hash_requested=%s",
                    "yes" if self._cfg.hash_requested else "no",
                )

                # Send our configured rate hint to sender (advisory)
                recv_rate_hint = self._cfg.rate_hint_mbps
                ctrl.send(
                    build_packet(PacketType.RATE_HINT, session_id, 0,
                                 build_rate_hint_payload(recv_rate_hint)),
                    feedback_dest,
                )
                logger.info(
                    "RATE_HINT → sender:%d  %.1f MB/s (%s)",
                    feedback_port, recv_rate_hint,
                    "unlimited" if recv_rate_hint == 0 else "active",
                )

                # ── Shared state ───────────────────────────────────────────────
                # claimed_chunks: chunks we have accepted and started processing
                # written_chunks: chunks fully written (disk mode only; in RAM
                #                 mode claimed == written so we reuse this set)
                claimed_chunks: Set[int] = set(initial_written)
                written_chunks: Set[int] = set(initial_written)
                chunks_lock               = threading.Lock()
                bytes_counter             = [0]   # bytes received (RAM) or written (disk)

                stop_recv_event  = threading.Event()
                stop_write_event = threading.Event()   # disk mode only

                sidecar_meta = {
                    "version": 1, "session_id": session_id.hex(),
                    "filename": filename, "file_size": file_size,
                    "total_chunks": total_chunks, "chunk_size": chunk_size,
                    "file_sha256": expected_sha.hex(),
                }
                sidecar_mgr = SidecarManager(output_path, sidecar_meta)

                recv_start = time.monotonic()

                # Peak and most-recent delivery rate — updated by the throughput
                # reporter thread and read by _control_loop for write_result().
                peak_recv_mbps = [0.0]
                last_recv_mbps = [0.0]

                if use_ram:
                    recv_threads = self._spawn_ram_receivers(
                        data_transports, session_id,
                        claimed_chunks, written_chunks, chunks_lock,
                        stop_recv_event, ram_buffer, bytes_counter,
                        feedback_transport, feedback_dest,
                    )
                    write_queue  = None
                    write_threads = []
                else:
                    recv_threads, write_threads, write_queue = self._spawn_disk_threads(
                        data_transports, session_id, output_path,
                        claimed_chunks, written_chunks, chunks_lock,
                        stop_recv_event, stop_write_event, sidecar_mgr,
                        total_chunks, chunk_size, file_size,
                        feedback_transport, feedback_dest, bytes_counter,
                    )

                # ── Phase 4: SACK sender thread ───────────────────────────────
                sack_stop   = threading.Event()
                if self._cfg.sack_enabled:
                    sack_thread = threading.Thread(
                        target=self._sack_sender_thread,
                        args=(
                            written_chunks, chunks_lock,
                            feedback_transport, feedback_dest,
                            session_id, sack_stop,
                            self._cfg.sack_interval_ms / 1_000.0,
                        ),
                        daemon=True, name="SACKSender",
                    )
                    sack_thread.start()
                    logger.info(
                        "SACKSender started  interval=%d ms → %s:%d",
                        self._cfg.sack_interval_ms,
                        feedback_dest[0], feedback_dest[1],
                    )
                else:
                    sack_thread = None
                    logger.info("SACKSender: disabled (sack_enabled=false)")

                # ── Throughput reporter ────────────────────────────────────────
                throughput_stop   = threading.Event()
                throughput_thread = threading.Thread(
                    target=self._throughput_report_thread,
                    args=(
                        bytes_counter, chunks_lock, written_chunks,
                        total_chunks, chunk_size,
                        feedback_transport, feedback_dest,
                        session_id, throughput_stop,
                        self._cfg.throughput_report_interval_ms / 1_000.0,
                        recv_start,
                        peak_recv_mbps, last_recv_mbps,
                    ),
                    daemon=True, name="ThroughputReport",
                )
                throughput_thread.start()

                # ── Progress reporter ──────────────────────────────────────────
                progress_stop   = threading.Event()
                progress_thread = threading.Thread(
                    target=self._progress_reporter_thread,
                    args=(
                        written_chunks, chunks_lock, total_chunks, chunk_size,
                        progress_stop,
                        self._cfg.progress_interval_ms / 1_000.0, recv_start,
                    ),
                    daemon=True, name="RecvProgress",
                )
                progress_thread.start()

                try:
                    return self._control_loop(
                        ctrl, sender_addr, feedback_transport, feedback_dest,
                        session_id, total_chunks, expected_sha, output_path,
                        written_chunks, claimed_chunks, chunks_lock,
                        stop_recv_event, stop_write_event,
                        recv_threads, write_threads, write_queue,
                        recv_timeout, recv_start, num_streams,
                        sidecar_mgr, progress_stop, throughput_stop,
                        bytes_counter,
                        use_ram=use_ram, ram_buffer=ram_buffer,
                        file_size=file_size, chunk_size=chunk_size,
                        sender_mac_key=sender_mac_key,
                        peak_recv_mbps=peak_recv_mbps,
                        last_recv_mbps=last_recv_mbps,
                    )
                finally:
                    sack_stop.set()
                    progress_stop.set()
                    throughput_stop.set()
                    stop_recv_event.set()
                    stop_write_event.set()
                    for t in recv_threads + write_threads:
                        t.join(timeout=5.0)

            finally:
                for dt in data_transports:
                    dt.close()
        finally:
            feedback_transport.close()

    # ── RAM receiver threads ───────────────────────────────────────────────────

    def _spawn_ram_receivers(
        self,
        data_transports, session_id,
        claimed_chunks, written_chunks, chunks_lock,
        stop_event, ram_buffer, bytes_counter,
        feedback_transport, feedback_dest,
    ):
        threads = []
        for stream_id, dt in enumerate(data_transports):
            t = threading.Thread(
                target=self._ram_receiver_thread,
                args=(
                    stream_id, dt, session_id,
                    claimed_chunks, written_chunks, chunks_lock,
                    stop_event, ram_buffer, bytes_counter,
                    feedback_transport, feedback_dest,
                ),
                daemon=True, name=f"RAMRecv-{stream_id}",
            )
            t.start()
            threads.append(t)
        logger.info("RAM receiver: %d threads started", len(threads))
        return threads

    def _ram_receiver_thread(
        self,
        stream_id, transport, session_id,
        claimed_chunks, written_chunks, chunks_lock,
        stop_event, ram_buffer, bytes_counter,
        feedback_transport, feedback_dest,
    ):
        """
        Receives chunks and writes directly into ram_buffer at byte_offset.
        No write queue — memory copies are near-instantaneous vs disk I/O.
        claimed_chunks and written_chunks stay in sync (both updated together).
        """
        pkts_received = pkts_dup = pkts_bad = 0
        while not stop_event.is_set():
            result = transport.recv(timeout=1.0)
            if result is None:
                continue
            raw, _ = result
            pkt = parse_packet(raw)
            if pkt is None or pkt.session_id != session_id or pkt.ptype != PacketType.DATA:
                continue
            try:
                chunk = parse_data_payload(pkt.payload)
            except ValueError as exc:
                logger.warning("RAMRecv-%d: malformed DATA: %s", stream_id, exc)
                pkts_bad += 1
                continue

            chunk_id    = chunk["chunk_id"]
            byte_offset = chunk["byte_offset"]
            data        = chunk["data"]
            checksum    = chunk["checksum"]

            with chunks_lock:
                if chunk_id in claimed_chunks:
                    pkts_dup += 1
                    continue
                claimed_chunks.add(chunk_id)

            # Decrypt
            if self._crypto.is_enabled:
                if len(data) < NONCE_LENGTH:
                    with chunks_lock:
                        claimed_chunks.discard(chunk_id)
                    self._send_nack(feedback_transport, feedback_dest, session_id, chunk_id)
                    pkts_bad += 1
                    continue
                nonce = data[:NONCE_LENGTH]
                try:
                    data = self._crypto.decrypt(nonce, data[NONCE_LENGTH:])
                except Exception as exc:
                    logger.warning("RAMRecv-%d: decrypt failed chunk %d: %s",
                                   stream_id, chunk_id, exc)
                    with chunks_lock:
                        claimed_chunks.discard(chunk_id)
                    self._send_nack(feedback_transport, feedback_dest, session_id, chunk_id)
                    pkts_bad += 1
                    continue

            # Verify
            if not verify_chunk_hash(data, checksum):
                logger.warning("RAMRecv-%d: hash FAIL chunk %d — sending NACK",
                               stream_id, chunk_id)
                with chunks_lock:
                    claimed_chunks.discard(chunk_id)
                self._send_nack(feedback_transport, feedback_dest, session_id, chunk_id)
                pkts_bad += 1
                continue

            # Write to RAM buffer — safe: non-overlapping byte ranges, GIL protects
            end = byte_offset + len(data)
            ram_buffer[byte_offset:end] = data

            with chunks_lock:
                written_chunks.add(chunk_id)
                bytes_counter[0] += len(data)

            pkts_received += 1

        logger.info(
            "RAMRecv-%d: stopped  recv=%d  dup=%d  bad=%d",
            stream_id, pkts_received, pkts_dup, pkts_bad,
        )

    # ── Disk receiver + writer threads ────────────────────────────────────────

    def _spawn_disk_threads(
        self,
        data_transports, session_id, output_path,
        claimed_chunks, written_chunks, chunks_lock,
        stop_recv_event, stop_write_event, sidecar_mgr,
        total_chunks, chunk_size, file_size,
        feedback_transport, feedback_dest, bytes_counter,
    ):
        write_queue    = queue.Queue(maxsize=_WRITE_QUEUE_MAX)
        flush_counter  = [0]
        flush_interval = self._cfg.sidecar_flush_interval

        recv_threads  = []
        write_threads = []

        for stream_id, dt in enumerate(data_transports):
            t = threading.Thread(
                target=self._data_receiver_thread,
                args=(stream_id, dt, session_id, claimed_chunks, chunks_lock,
                      stop_recv_event, write_queue),
                daemon=True, name=f"DataRecv-{stream_id}",
            )
            t.start()
            recv_threads.append(t)

        for writer_id in range(_NUM_WRITERS):
            t = threading.Thread(
                target=self._chunk_writer_thread,
                args=(
                    writer_id, write_queue, output_path,
                    claimed_chunks, written_chunks, chunks_lock,
                    stop_write_event, sidecar_mgr, flush_counter, flush_interval,
                    feedback_transport, feedback_dest, session_id,
                    bytes_counter,
                ),
                daemon=True, name=f"ChunkWriter-{writer_id}",
            )
            t.start()
            write_threads.append(t)

        return recv_threads, write_threads, write_queue

    def _data_receiver_thread(
        self, stream_id, transport, session_id,
        claimed_chunks, chunks_lock, stop_event, write_queue,
    ):
        pkts_received = pkts_dup = pkts_bad = 0
        while not stop_event.is_set():
            result = transport.recv(timeout=1.0)
            if result is None:
                continue
            raw, _ = result
            pkt = parse_packet(raw)
            if pkt is None or pkt.session_id != session_id or pkt.ptype != PacketType.DATA:
                continue
            try:
                chunk = parse_data_payload(pkt.payload)
            except ValueError as exc:
                logger.warning("DataRecv-%d: malformed DATA: %s", stream_id, exc)
                pkts_bad += 1
                continue

            chunk_id = chunk["chunk_id"]
            with chunks_lock:
                if chunk_id in claimed_chunks:
                    pkts_dup += 1
                    continue
                claimed_chunks.add(chunk_id)

            try:
                write_queue.put(chunk, timeout=5.0)
                pkts_received += 1
            except queue.Full:
                logger.warning("DataRecv-%d: write queue full — dropping chunk %d",
                               stream_id, chunk_id)
                with chunks_lock:
                    claimed_chunks.discard(chunk_id)
                pkts_bad += 1

        logger.info(
            "DataRecv-%d: stopped  recv=%d  dup=%d  bad=%d",
            stream_id, pkts_received, pkts_dup, pkts_bad,
        )

    def _chunk_writer_thread(
        self,
        writer_id, write_queue, output_path,
        claimed_chunks, written_chunks, chunks_lock,
        stop_event, sidecar_mgr, flush_counter, flush_interval,
        feedback_transport, feedback_dest, session_id,
        bytes_counter,
    ):
        chunks_written = chunks_failed = 0
        with open(output_path, "r+b") as fh:
            while not stop_event.is_set() or not write_queue.empty():
                try:
                    chunk = write_queue.get(timeout=0.5)
                except queue.Empty:
                    continue

                chunk_id    = chunk["chunk_id"]
                byte_offset = chunk["byte_offset"]
                data        = chunk["data"]
                checksum    = chunk["checksum"]

                # Decrypt
                if self._crypto.is_enabled:
                    if len(data) < NONCE_LENGTH:
                        with chunks_lock:
                            claimed_chunks.discard(chunk_id)
                        self._send_nack(feedback_transport, feedback_dest,
                                        session_id, chunk_id)
                        chunks_failed += 1
                        write_queue.task_done()
                        continue
                    nonce = data[:NONCE_LENGTH]
                    try:
                        data = self._crypto.decrypt(nonce, data[NONCE_LENGTH:])
                    except Exception as exc:
                        logger.warning("Writer-%d: decrypt failed chunk %d: %s",
                                       writer_id, chunk_id, exc)
                        with chunks_lock:
                            claimed_chunks.discard(chunk_id)
                        self._send_nack(feedback_transport, feedback_dest,
                                        session_id, chunk_id)
                        chunks_failed += 1
                        write_queue.task_done()
                        continue

                # Verify
                if not verify_chunk_hash(data, checksum):
                    logger.warning("Writer-%d: hash FAIL chunk %d — sending NACK",
                                   writer_id, chunk_id)
                    with chunks_lock:
                        claimed_chunks.discard(chunk_id)
                    self._send_nack(feedback_transport, feedback_dest,
                                    session_id, chunk_id)
                    chunks_failed += 1
                    write_queue.task_done()
                    continue

                # Write
                try:
                    fh.seek(byte_offset)
                    fh.write(data)
                    with chunks_lock:
                        written_chunks.add(chunk_id)
                        bytes_counter[0] += len(data)
                    chunks_written += 1

                    flush_counter[0] += 1
                    if flush_counter[0] % flush_interval == 0:
                        with chunks_lock:
                            snapshot = set(written_chunks)
                        sidecar_mgr.flush_snapshot(snapshot)
                except OSError as exc:
                    logger.error("Writer-%d: write failed chunk %d: %s",
                                 writer_id, chunk_id, exc)
                    with chunks_lock:
                        claimed_chunks.discard(chunk_id)
                    chunks_failed += 1
                finally:
                    write_queue.task_done()

        logger.info(
            "Writer-%d: stopped  written=%d  failed=%d",
            writer_id, chunks_written, chunks_failed,
        )

    # ── SACK helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _chunks_to_ranges(chunk_ids: List[int]) -> List[Tuple[int, int]]:
        """
        Convert a sorted list of chunk IDs into run-length encoded ranges.

        Example: [0,1,2,5,6,10] → [(0,3),(5,2),(10,1)]

        chunk_ids MUST be sorted ascending before calling this function.
        """
        if not chunk_ids:
            return []
        ranges: List[Tuple[int, int]] = []
        start = chunk_ids[0]
        run   = 1
        for cid in chunk_ids[1:]:
            if cid == start + run:
                run += 1
            else:
                ranges.append((start, run))
                start = cid
                run   = 1
        ranges.append((start, run))
        return ranges

    def _sack_sender_thread(
        self,
        written_chunks: Set[int],
        chunks_lock:    threading.Lock,
        feedback_transport,
        feedback_dest:  Tuple[str, int],
        session_id:     bytes,
        stop_event:     threading.Event,
        interval_s:     float,
    ) -> None:
        """
        Periodically sends SACK packets to the sender on the feedback channel.

        Wakes every interval_s, snapshots written_chunks under the lock,
        computes run-length encoded ranges, and sends a SACK packet.

        This gives the sender a continuous view of which chunks have been
        received and acknowledged, allowing it to release window slots and
        derive the missing set without waiting for FINISH.
        """
        while not stop_event.wait(timeout=interval_s):
            with chunks_lock:
                sorted_ids = sorted(written_chunks)

            if not sorted_ids:
                continue

            ranges = self._chunks_to_ranges(sorted_ids)
            try:
                pkt = build_packet(
                    PacketType.SACK, session_id, 0,
                    build_sack_payload(ranges),
                )
                feedback_transport.send(pkt, feedback_dest)
                logger.debug(
                    "SACK sent: %d range(s)  covering %d chunks → %s:%d",
                    len(ranges), len(sorted_ids),
                    feedback_dest[0], feedback_dest[1],
                )
            except OSError as exc:
                logger.debug("SACK send error: %s", exc)

    # ── NACK helper ───────────────────────────────────────────────────────────

    def _send_nack(self, transport, dest, session_id, chunk_id):
        try:
            pkt = build_packet(PacketType.NACK, session_id, 0,
                               build_nack_payload(chunk_id))
            transport.send(pkt, dest)
        except OSError as exc:
            logger.debug("NACK send error chunk %d: %s", chunk_id, exc)

    # ── THROUGHPUT_REPORT thread ───────────────────────────────────────────────

    def _throughput_report_thread(
        self,
        bytes_counter, chunks_lock, written_chunks,
        total_chunks, chunk_size,
        feedback_transport, feedback_dest,
        session_id, stop_event,
        interval_s, recv_start,
        peak_recv_mbps, last_recv_mbps,
    ):
        """
        Sends THROUGHPUT_REPORT to sender every interval_s.

        This gives the sender a real-time view of the receiver's actual
        write/buffer throughput (stable_mbps in the pacing engine).

        Automatic RATE_HINT generation has been removed.  The step-climb
        pacing engine finds the ceiling via WSAENOBUFS — that is the correct
        mechanism.  An operator-configured rate_hint_mbps in config.json is
        the only way to cap the sender's target rate from the receiver side.
        Auto-generated hints consistently misfired (firing too early or below
        the receiver's demonstrated capacity) and created self-reinforcing
        downward spirals.

        peak_recv_mbps[0] and last_recv_mbps[0] are shared with _control_loop
        via one-element lists so write_result() can record accurate throughput
        statistics without querying a separate data structure.
        """
        last_bytes = 0
        last_t     = recv_start

        while not stop_event.wait(timeout=interval_s):
            now = time.monotonic()

            with chunks_lock:
                current_bytes  = bytes_counter[0]
                chunks_written = len(written_chunks)

            window_bytes = current_bytes - last_bytes
            window_ms    = max(1, int((now - last_t) * 1_000))
            elapsed_ms   = max(1, int((now - recv_start) * 1_000))

            if window_bytes == 0:
                last_t = now
                continue

            try:
                pkt = build_packet(
                    PacketType.THROUGHPUT_REPORT, session_id, 0,
                    build_throughput_report_payload(
                        window_bytes, window_ms,
                        current_bytes, elapsed_ms, chunks_written,
                    ),
                )
                feedback_transport.send(pkt, feedback_dest)
            except OSError as exc:
                logger.debug("THROUGHPUT_REPORT send error: %s", exc)

            rate_mbps = window_bytes / window_ms * 1_000 / 1_048_576
            last_recv_mbps[0] = rate_mbps
            if rate_mbps > peak_recv_mbps[0]:
                peak_recv_mbps[0] = rate_mbps

            logger.debug(
                "THROUGHPUT_REPORT: %.1f MB/s  %d/%d chunks  window=%dms",
                rate_mbps, chunks_written, total_chunks, window_ms,
            )

            last_bytes = current_bytes
            last_t     = now

    # ── File write from RAM buffer ─────────────────────────────────────────────

    def _write_ram_buffer_to_disk(self, output_path: str, ram_buffer: bytearray,
                                   file_size: int,
                                   expected_sha256: bytes = b"") -> tuple:
        """
        Writes the RAM buffer to disk in one sequential write.
        Returns (sha256_digest, sha_elapsed_s, sha_speed_mbps).
        sha256_digest is bytes(32) when receiver_file_hash_enabled is False.
        """
        logger.info("Writing %.1f MB from RAM buffer to disk …",
                    file_size / 1_048_576)
        t0 = time.monotonic()
        with open(output_path, "wb") as fh:
            fh.write(ram_buffer)
        elapsed    = time.monotonic() - t0
        write_mbps = (file_size / elapsed / 1_048_576) if elapsed > 0 else 0.0
        logger.info("Disk write: %.1f MB in %.2fs = %.1f MB/s",
                    file_size / 1_048_576, elapsed, write_mbps)

        if expected_sha256 == bytes(32) or not expected_sha256:
            logger.info("Sender sent zero hash — skipping file SHA-256")
            return bytes(32), 0.0, 0.0

        logger.info("Computing SHA-256 from RAM buffer …")
        t0 = time.monotonic()
        h  = hashlib.sha256()
        for offset in range(0, file_size, _SHA_BLOCK):
            h.update(ram_buffer[offset: offset + _SHA_BLOCK])
        digest     = h.digest()
        sha_el     = time.monotonic() - t0
        sha_mbps   = (file_size / sha_el / 1_048_576) if sha_el > 0 else 0.0
        logger.info("SHA-256 (RAM): %.1f MB/s  %s", sha_mbps, format_hex(digest))
        return digest, sha_el, sha_mbps

    # ── Write queue drain helper (disk mode) ──────────────────────────────────

    @staticmethod
    def _drain_write_queue(wq: queue.Queue, timeout: float = 30.0) -> bool:
        """
        Block until write_queue is empty (all task_done() called) or timeout.
        Returns True if drained cleanly, False on timeout.
        """
        done = threading.Event()
        def _join():
            wq.join()
            done.set()
        t = threading.Thread(target=_join, daemon=True)
        t.start()
        return done.wait(timeout=timeout)

    # ── Resume state ──────────────────────────────────────────────────────────

    def _load_resume_state(self, output_path, meta, session_id) -> Set[int]:
        if not self._cfg.resume_enabled:
            return set()
        sidecar_data = SidecarManager.load(output_path)
        if sidecar_data is None:
            return set()
        if not self._validate_sidecar(sidecar_data, meta):
            logger.warning("RESUME: sidecar mismatch — ignoring")
            return set()
        raw_ids = sidecar_data.get("written_chunks", [])
        if not isinstance(raw_ids, list):
            return set()
        total_chunks = meta["total_chunks"]
        loaded = {int(cid) for cid in raw_ids if 0 <= int(cid) < total_chunks}
        logger.info("RESUME: loaded %d/%d chunks", len(loaded), total_chunks)
        return loaded

    @staticmethod
    def _validate_sidecar(sidecar: dict, meta: dict) -> bool:
        return (
            sidecar.get("filename")      == meta["filename"]
            and sidecar.get("file_size")    == meta["file_size"]
            and sidecar.get("total_chunks") == meta["total_chunks"]
            and sidecar.get("chunk_size")   == meta["chunk_size"]
            and sidecar.get("file_sha256")  == meta["file_sha256"].hex()
        )

    # ── Handshake helpers ─────────────────────────────────────────────────────

    def _wait_for_init(self, ctrl, recv_timeout):
        """
        Wait for an INIT packet.  Returns (session_id, addr, num_streams, sender_mac_key).
        sender_mac_key is "" when the sender did not include one (old sender).
        """
        logger.info("Waiting for INIT …")
        deadline = time.monotonic() + recv_timeout
        while time.monotonic() < deadline:
            result = ctrl.recv(timeout=min(deadline - time.monotonic(), 5.0))
            if result is None:
                continue
            data, addr = result
            pkt = parse_packet(data)
            if pkt is None or pkt.ptype != PacketType.INIT:
                continue
            hex_id = pkt.session_id.hex()
            with FileReceiver._blackout_lock:
                expiry = FileReceiver._blackout.get(hex_id, 0.0)
            if expiry > time.monotonic():
                logger.info("INIT session=%s IGNORED — blackout", hex_id[:16])
                continue
            try:
                info           = parse_init_payload(pkt.payload)
                num_streams    = max(1, info.get("num_streams", 1))
                sender_mac_key = info.get("sender_mac_key", "")
                logger.info(
                    "INIT from %s:%d  session=%s  version=%d  streams=%d  "
                    "sender_key=%s",
                    addr[0], addr[1], hex_id[:16],
                    info.get("version", 1), num_streams,
                    (sender_mac_key[:8] + "…") if sender_mac_key else "(none)",
                )
                return pkt.session_id, addr, num_streams, sender_mac_key
            except Exception as exc:
                logger.warning("Bad INIT from %s:%d — %s", addr[0], addr[1], exc)
        raise RuntimeError(f"Timed out waiting for INIT ({recv_timeout:.0f}s)")

    def _wait_for_meta(self, ctrl, session_id, sender_addr, recv_timeout):
        deadline = time.monotonic() + recv_timeout
        while time.monotonic() < deadline:
            result = ctrl.recv(timeout=min(deadline - time.monotonic(), 5.0))
            if result is None:
                continue
            data, _ = result
            pkt = parse_packet(data)
            if pkt is None or pkt.session_id != session_id:
                continue
            if pkt.ptype == PacketType.INIT:
                ctrl.send(
                    build_packet(PacketType.ACK, session_id, 0,
                                 build_ack_payload(PacketType.INIT)),
                    sender_addr,
                )
                continue
            if pkt.ptype == PacketType.META:
                try:
                    return parse_meta_payload(pkt.payload)
                except Exception as exc:
                    logger.warning("Bad META: %s", exc)
                    ctrl.send(
                        build_packet(PacketType.ERROR, session_id, 0,
                                     build_error_payload(1, f"META parse error: {exc}")),
                        sender_addr,
                    )
        raise RuntimeError("Timed out waiting for META")

    # ── Socket management ─────────────────────────────────────────────────────

    def _open_data_sockets(self, data_base, num_streams):
        buf_size   = self._cfg.socket_buffer_size
        transports = []
        logger.info("Opening %d data sockets (requesting %d MB buffers) …",
                    num_streams, buf_size // 1_048_576)
        try:
            for i in range(num_streams):
                dt = UDPTransport(("", data_base + i), buffer_size=buf_size)
                transports.append(dt)
                logger.info(
                    "Data socket %d bound to port %d  "
                    "(SO_RCVBUF=%d MB  SO_SNDBUF=%d MB)",
                    i, data_base + i, dt.rcvbuf_mb, dt.sndbuf_mb,
                )
        except OSError as exc:
            for dt in transports:
                dt.close()
            raise RuntimeError(f"Failed to open data socket: {exc}") from exc
        return transports

    # ── File pre-allocation ───────────────────────────────────────────────────

    @staticmethod
    def _preallocate_file(path: str, file_size: int) -> None:
        logger.info("Pre-allocating: %s  (%d bytes)", path, file_size)
        with open(path, "wb") as fh:
            if file_size > 0:
                fh.seek(file_size - 1)
                fh.write(b"\x00")

    # ── RESEND batching ───────────────────────────────────────────────────────

    def _send_resend_batched(self, feedback_transport, feedback_dest,
                             session_id, missing: List[int]) -> int:
        # Sort ascending so sender retransmits oldest (lowest) chunk IDs first.
        missing = sorted(missing)
        n_ids  = len(missing)
        n_pkts = 0
        offset = 0
        while offset < n_ids:
            batch = missing[offset: offset + _MAX_IDS_PER_RESEND]
            pkt   = build_packet(PacketType.RESEND, session_id, 0,
                                 build_resend_payload(batch))
            feedback_transport.send(pkt, feedback_dest)
            n_pkts += 1
            offset += len(batch)
        logger.info(
            "RESEND: %d chunk IDs in %d packet(s) → %s:%d",
            n_ids, n_pkts, feedback_dest[0], feedback_dest[1],
        )
        return n_pkts

    # ── Progress reporter ─────────────────────────────────────────────────────

    def _progress_reporter_thread(
        self, written_chunks, chunks_lock, total_chunks, chunk_size,
        stop_event, interval_s, recv_start,
    ):
        last_n = 0
        last_t = recv_start
        while not stop_event.wait(timeout=interval_s):
            with chunks_lock:
                n_written = len(written_chunks)
            now     = time.monotonic()
            elapsed = now - recv_start
            delta_n = n_written - last_n
            delta_t = now - last_t
            inst_mbps = (delta_n * chunk_size / 1_048_576 / delta_t) if delta_t > 0 else 0.0
            remaining = total_chunks - n_written
            cps   = (delta_n / delta_t) if delta_n > 0 and delta_t > 0 else \
                    (n_written / elapsed if elapsed > 0 else 0.0)
            eta_s = (remaining / cps) if cps > 0 else float("inf")
            eta_str = f"{eta_s:.0f}s" if eta_s < 86_400 else "∞"
            pct   = (n_written / total_chunks * 100.0) if total_chunks else 0.0
            logger.info(
                "[PROGRESS-RX] %d/%d (%.1f%%)  %.1f MB/s  "
                "ETA=%s  elapsed=%.1fs",
                n_written, total_chunks, pct, inst_mbps, eta_str, elapsed,
            )
            last_n = n_written
            last_t = now

    # ── Control loop ──────────────────────────────────────────────────────────

    def _control_loop(
        self,
        ctrl, sender_addr, feedback_transport, feedback_dest,
        session_id, total_chunks, expected_sha256, output_path,
        written_chunks, claimed_chunks, chunks_lock,
        stop_recv_event, stop_write_event,
        recv_threads, write_threads, write_queue,
        recv_timeout, recv_start, num_streams,
        sidecar_mgr, progress_stop, throughput_stop,
        bytes_counter,
        use_ram: bool = False,
        ram_buffer: Optional[bytearray] = None,
        file_size: int = 0,
        chunk_size: int = 0,
        sender_mac_key: str = "",
        peak_recv_mbps: Optional[list] = None,
        last_recv_mbps: Optional[list] = None,
    ) -> str:
        if peak_recv_mbps is None:
            peak_recv_mbps = [0.0]
        if last_recv_mbps is None:
            last_recv_mbps = [0.0]

        deadline          = time.monotonic() + recv_timeout
        finish_count      = 0
        recv_loss_passes: list = []   # per-pass loss records sent by sender via LOSS_REPORT

        while time.monotonic() < deadline:
            result = ctrl.recv(timeout=min(deadline - time.monotonic(), 5.0))
            if result is None:
                continue

            data, _ = result
            pkt = parse_packet(data)
            if pkt is None or pkt.session_id != session_id:
                continue

            if pkt.ptype == PacketType.PING:
                # Echo the payload EXACTLY as PONG on the feedback channel.
                # Sender computes RTT = now - sent_timestamp_ns on receipt.
                try:
                    feedback_transport.send(
                        build_packet(PacketType.PONG, session_id, 0, pkt.payload),
                        feedback_dest,
                    )
                    ts_ns = parse_ping_payload(pkt.payload)
                    logger.debug("PING → PONG  ts_ns=%d", ts_ns)
                except Exception as exc:
                    logger.debug("PONG send error: %s", exc)
                continue

            if pkt.ptype == PacketType.RATE_HINT:
                rate = parse_rate_hint_payload(pkt.payload)
                logger.info("RATE_HINT from sender: %.1f MB/s (stored)", rate)
                continue

            if pkt.ptype == PacketType.META:
                ctrl.send(
                    build_packet(PacketType.ACK, session_id, 0,
                                 build_ack_payload(PacketType.META)),
                    sender_addr,
                )
                continue

            if pkt.ptype == PacketType.LOSS_REPORT:
                try:
                    lr = parse_loss_report_payload(pkt.payload)
                    recv_loss_passes.append({
                        "pass_index":        lr["pass_index"],
                        "chunks_sent":       lr["chunks_sent"],
                        "chunks_lost":       lr["chunks_lost"],
                        "pass_duration_sec": lr["pass_duration_sec"],
                    })
                    logger.debug(
                        "LOSS_REPORT pass=%d  sent=%d  lost=%d  "
                        "rate=%.1f MB/s  tier=%d",
                        lr["pass_index"], lr["chunks_sent"], lr["chunks_lost"],
                        lr["current_mbps"], lr["tier"],
                    )
                except Exception as exc:
                    logger.debug("LOSS_REPORT parse error: %s", exc)
                continue

            if pkt.ptype != PacketType.FINISH:
                continue

            finish_count += 1
            logger.info("FINISH #%d received", finish_count)

            # ── Drain write queue before audit (disk mode only) ───────────────
            # In disk mode, chunks may be received but not yet written when
            # FINISH arrives.  Without draining, they appear "missing" and
            # trigger a massive unnecessary RESEND pass.
            # In RAM mode the write is inline so there is no queue to drain.
            if not use_ram and write_queue is not None:
                logger.info("Draining write queue before audit …")
                drained = self._drain_write_queue(write_queue, timeout=30.0)
                if not drained:
                    logger.warning("Write queue drain timed out — auditing anyway")

            # ── Chunk audit ───────────────────────────────────────────────────
            with chunks_lock:
                n_written = len(written_chunks)
                missing   = sorted(
                    cid for cid in range(total_chunks)
                    if cid not in written_chunks
                )

            logger.info(
                "Chunk audit: %d/%d written, %d missing",
                n_written, total_chunks, len(missing),
            )

            if missing:
                if len(missing) <= 20:
                    logger.info("Missing: %s", missing)
                else:
                    logger.info("Missing (first 20 of %d): %s …",
                                len(missing), missing[:20])
                self._send_resend_batched(feedback_transport, feedback_dest,
                                          session_id, missing)
                deadline = time.monotonic() + recv_timeout

            else:
                # ── All chunks present ────────────────────────────────────────
                # data_receive_elapsed = pure receive time, no SHA
                data_receive_elapsed = time.monotonic() - recv_start
                logger.info("All %d chunks present — beginning shutdown …", total_chunks)

                stop_recv_event.set()
                for t in recv_threads:
                    t.join(timeout=15.0)

                if not use_ram and write_queue is not None:
                    write_queue.join()
                    stop_write_event.set()
                    for t in write_threads:
                        t.join(timeout=30.0)

                throughput_stop.set()
                progress_stop.set()

                if self._cfg.resume_enabled and not use_ram:
                    with chunks_lock:
                        sidecar_mgr.flush_snapshot(set(written_chunks))

                # ── SHA-256 / disk write ──────────────────────────────────────
                # status_msg is updated by the background thread so the sender's
                # log shows exactly what the receiver is doing during the wait.
                status_msg = ["Receiver: preparing …"]

                def _build_finish_ack(msg: str) -> bytes:
                    """
                    FINISH-ACK extended payload: [ACK_TYPE, ...status_utf8]
                    Byte 0 = ACK type (0x06 = FINISH), bytes 1+ = status string.
                    Sender reads byte 0 for the ACK check; bytes 1+ for the log.
                    Backward compatible — old senders ignore bytes after byte 0.
                    """
                    return build_packet(
                        PacketType.ACK, session_id, 0,
                        bytes([int(PacketType.FINISH)]) + msg.encode("utf-8")[:120],
                    )

                if use_ram:
                    sha_result: dict = {}

                    def _do_ram_write():
                        status_msg[0] = "Receiver: writing RAM buffer to disk …"
                        try:
                            digest, sha_el, sha_sp = self._write_ram_buffer_to_disk(
                                output_path, ram_buffer, file_size, expected_sha256
                            )
                            if digest != bytes(32):
                                status_msg[0] = "Receiver: computing SHA-256 from RAM …"
                            sha_result["digest"]  = digest
                            sha_result["elapsed"] = sha_el
                            sha_result["speed"]   = sha_sp
                        except Exception as exc:
                            sha_result["error"] = exc

                    sha_thread = threading.Thread(
                        target=_do_ram_write, daemon=True, name="RAMWrite"
                    )
                    sha_thread.start()
                else:
                    sha_result = {}
                    _should_verify = (expected_sha256 != bytes(32))
                    if _should_verify:
                        logger.info("Computing whole-file SHA-256 from disk …")
                        status_msg[0] = "Receiver: computing SHA-256 from disk …"
                        def _do_sha():
                            try:
                                t0     = time.monotonic()
                                digest = compute_file_sha256(output_path)
                                sha_el = time.monotonic() - t0
                                sha_result["digest"]  = digest
                                sha_result["elapsed"] = sha_el
                                sha_result["speed"]   = (
                                    file_size / sha_el / 1_048_576
                                    if sha_el > 0 else 0.0
                                )
                            except Exception as exc:
                                sha_result["error"] = exc
                        sha_thread = threading.Thread(
                            target=_do_sha, daemon=True, name="SHA-Worker"
                        )
                        sha_thread.start()
                    else:
                        logger.info("Sender sent zero hash — skipping file SHA-256")
                        status_msg[0] = "Receiver: no SHA-256 required"
                        sha_result["digest"]  = bytes(32)
                        sha_result["elapsed"] = 0.0
                        sha_result["speed"]   = 0.0
                        sha_thread = None

                # Keep ACK-ing FINISH while disk write / SHA runs.
                # Each ACK carries the current status string so the sender's
                # log shows exactly what the receiver is doing.
                sha_deadline  = time.monotonic() + recv_timeout
                active_thread = sha_thread
                while (active_thread is not None
                       and active_thread.is_alive()
                       and time.monotonic() < sha_deadline):
                    r = ctrl.recv(timeout=1.0)
                    if r:
                        p = parse_packet(r[0])
                        if p and p.session_id == session_id and p.ptype == PacketType.FINISH:
                            ctrl.send(_build_finish_ack(status_msg[0]), sender_addr)
                    active_thread.join(timeout=0.0)

                if active_thread is not None and active_thread.is_alive():
                    raise RuntimeError(f"SHA-256/write timed out after {recv_timeout:.0f}s")
                if "error" in sha_result:
                    raise RuntimeError(f"SHA-256/write failed: {sha_result['error']}")

                actual_sha  = sha_result["digest"]
                sha_elapsed = sha_result.get("elapsed", 0.0)
                sha_speed   = sha_result.get("speed",   0.0)
                _ZERO_SHA   = bytes(32)
                # Verification is active when:
                #   - The sender sent a real (non-zero) hash in FINISH, AND
                #   - We actually computed a digest (receiver_file_hash_enabled
                #     or hash_required forced it)
                sha_enabled = (expected_sha256 != _ZERO_SHA
                               and actual_sha  != _ZERO_SHA)

                # ── SHA mismatch → COMPLETE(1) ────────────────────────────────
                if sha_enabled and actual_sha != expected_sha256:
                    logger.error(
                        "SHA-256 MISMATCH  expected=%s  got=%s",
                        format_hex(expected_sha256), format_hex(actual_sha),
                    )
                    complete_pkt = build_packet(
                        PacketType.COMPLETE, session_id, 0, build_complete_payload(1)
                    )
                    for _ in range(3):
                        ctrl.send(complete_pkt, sender_addr)
                        time.sleep(0.05)
                    total_elapsed = time.monotonic() - recv_start
                    self._print_summary(
                        filename=os.path.basename(output_path),
                        success=False,
                        fail_reason="SHA-256 mismatch",
                        sha_enabled=sha_enabled,
                        sha_elapsed=sha_elapsed,
                        sha_speed=sha_speed,
                        actual_mbps=(file_size / data_receive_elapsed / 1_048_576
                                     if data_receive_elapsed > 0 else 0.0),
                        net_mbps=(file_size / total_elapsed / 1_048_576),
                    )
                    # start_mbps=0.0: receiver has no ramp profile (see peer_db docstring)
                    _net_mbps_fail = (file_size / total_elapsed / 1_048_576
                                      if total_elapsed > 0 else 0.0)
                    transfer_id = peer_db.write_result(
                        sender_mac_key, "recv",
                        0.0, peak_recv_mbps[0], last_recv_mbps[0],
                        expected_sha256.hex(), total_elapsed, success=0,
                        avg_mbps=_net_mbps_fail, max_mbps=peak_recv_mbps[0], tier=0,
                    )
                    peer_db.write_loss_passes(transfer_id, recv_loss_passes)
                    self._write_metrics(
                        session_id=session_id,
                        output_path=output_path,
                        file_size=file_size,
                        total_chunks=total_chunks,
                        chunk_size=chunk_size,
                        num_streams=num_streams,
                        recv_start=recv_start,
                        written_chunks_count=len(written_chunks),
                        success=False,
                        failure_reason="SHA-256 mismatch",
                    )
                    raise RuntimeError("SHA-256 mismatch")

                # ── Success → COMPLETE(0) ─────────────────────────────────────
                net_elapsed  = time.monotonic() - recv_start
                actual_mbps  = (file_size / data_receive_elapsed / 1_048_576
                                if data_receive_elapsed > 0 else 0.0)
                net_mbps     = (file_size / net_elapsed / 1_048_576
                                if net_elapsed > 0 else 0.0)

                if sha_enabled:
                    logger.info("SHA-256 verified: %s ✓", format_hex(actual_sha))

                self._print_summary(
                    filename=os.path.basename(output_path),
                    success=True,
                    fail_reason="",
                    sha_enabled=sha_enabled,
                    sha_elapsed=sha_elapsed,
                    sha_speed=sha_speed,
                    actual_mbps=actual_mbps,
                    net_mbps=net_mbps,
                )

                complete_pkt = build_packet(
                    PacketType.COMPLETE, session_id, 0, build_complete_payload(0)
                )
                for _ in range(3):
                    ctrl.send(complete_pkt, sender_addr)
                    time.sleep(0.05)

                sidecar_mgr.delete()
                self._add_to_blackout(session_id, self._cfg.session_blackout_s)

                # start_mbps=0.0: receiver has no ramp profile (see peer_db docstring)
                transfer_id = peer_db.write_result(
                    sender_mac_key, "recv",
                    0.0, peak_recv_mbps[0], last_recv_mbps[0],
                    expected_sha256.hex(), net_elapsed, success=1,
                    avg_mbps=net_mbps, max_mbps=peak_recv_mbps[0], tier=0,
                )
                peer_db.write_loss_passes(transfer_id, recv_loss_passes)
                self._write_metrics(
                    session_id=session_id,
                    output_path=output_path,
                    file_size=file_size,
                    total_chunks=total_chunks,
                    chunk_size=chunk_size,
                    num_streams=num_streams,
                    recv_start=recv_start,
                    written_chunks_count=len(written_chunks),
                    success=True,
                )
                return output_path

        total_elapsed  = time.monotonic() - recv_start
        _net_mbps_tout = (file_size / total_elapsed / 1_048_576
                          if total_elapsed > 0 else 0.0)
        # start_mbps=0.0: receiver has no ramp profile (see peer_db docstring)
        transfer_id = peer_db.write_result(
            sender_mac_key, "recv",
            0.0, peak_recv_mbps[0], last_recv_mbps[0],
            expected_sha256.hex(), total_elapsed, success=0,
            avg_mbps=_net_mbps_tout, max_mbps=peak_recv_mbps[0], tier=0,
        )
        peer_db.write_loss_passes(transfer_id, recv_loss_passes)
        self._write_metrics(
            session_id=session_id,
            output_path=output_path,
            file_size=file_size,
            total_chunks=total_chunks,
            chunk_size=chunk_size,
            num_streams=num_streams,
            recv_start=recv_start,
            written_chunks_count=len(written_chunks),
            success=False,
            failure_reason="timeout",
        )
        raise RuntimeError(
            f"Receiver timed out after {recv_timeout:.0f}s "
            f"({len(written_chunks)}/{total_chunks} chunks)"
        )

    # ── Metrics writer ────────────────────────────────────────────────────────

    def _write_metrics(
        self,
        session_id: bytes,
        output_path: str,
        file_size: int,
        total_chunks: int,
        chunk_size: int,
        num_streams: int,
        recv_start: float,
        written_chunks_count: int,
        success: bool,
        failure_reason: str = "",
    ) -> None:
        """Write receiver transfer metrics to .ft_metrics_recv.json if metrics_enabled."""
        if not self._cfg.metrics_enabled:
            return
        duration_s = time.monotonic() - recv_start
        throughput = (file_size / duration_s / 1_048_576) if duration_s > 0 else 0.0
        metrics = {
            "side":             "receiver",
            "session_id":       session_id.hex(),
            "filename":         os.path.basename(output_path),
            "file_size":        file_size,
            "total_chunks":     total_chunks,
            "chunk_size":       chunk_size,
            "num_streams":      num_streams,
            "duration_s":       round(duration_s, 3),
            "throughput_mbps":  round(throughput, 2),
            "chunks_written":   written_chunks_count,
            "success":          success,
            "failure_reason":   failure_reason,
        }
        metrics_path = self._cfg.metrics_file.replace(
            ".ft_metrics", ".ft_metrics_recv"
        )
        try:
            with open(metrics_path, "w", encoding="utf-8") as fh:
                json.dump(metrics, fh, indent=2)
            logger.info("Receiver metrics -> %s", metrics_path)
        except OSError as exc:
            logger.warning("Failed to write receiver metrics: %s", exc)

    # ── Transfer summary ──────────────────────────────────────────────────────

    @staticmethod
    def _print_summary(
        filename: str,
        success: bool,
        fail_reason: str,
        sha_enabled: bool,
        sha_elapsed: float,
        sha_speed: float,
        actual_mbps: float,
        net_mbps: float,
    ) -> None:
        bar   = "=" * 82
        label = "successful" if success else f"failed — {fail_reason}"

        if sha_enabled and sha_elapsed > 0:
            sha_status = (f"enabled — {sha_elapsed:.2f}s at "
                          f"{sha_speed:.1f} MB/s")
        else:
            sha_status = "disabled"

        lines = [
            bar,
            f"  Transfer of '{filename}' {label}",
            f"  Receiver SHA-256 {sha_status}",
            f"  Actual receive speed:  {actual_mbps:.1f} MB/s  "
            f"(data transfer only)",
            f"  Net receive speed:     {net_mbps:.1f} MB/s  "
            f"(transfer + write + SHA)",
            bar,
        ]
        for line in lines:
            logger.info(line)

    # ── Session blackout ──────────────────────────────────────────────────────

    @classmethod
    def _add_to_blackout(cls, session_id: bytes, blackout_s: float) -> None:
        if blackout_s <= 0.0:
            return
        hex_id = session_id.hex()
        now    = time.monotonic()
        with cls._blackout_lock:
            cls._blackout[hex_id] = now + blackout_s
            expired = [k for k, v in cls._blackout.items() if v <= now]
            for k in expired:
                del cls._blackout[k]
