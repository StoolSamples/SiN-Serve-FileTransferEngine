"""
stream_manager.py — Multi-stream UDP send engine (Phase 3).

StreamManager encapsulates all stream worker threads for a single file
transfer pass.  It is designed to replace the inline stream-worker code
in sender.py (Task 2) without breaking any existing behaviour.

Architecture
────────────
  • One worker thread per UDP stream (data_transports[i] → data_base_port+i)
  • Shared work_queue distributes chunk IDs across workers (no duplication)
  • _STOP sentinel fans out: each worker re-puts it so every sibling sees it
  • Atomic live counters — GIL-protected single-element list assignments;
    intentionally lock-free because these counters are display-only
  • ScalingHook is advisory only in Phase 3: probe loop logs decisions,
    no live resize is performed

Phase 3 limitations (by design):
  • Fixed stream count — determined at construction
  • No live stream add/remove — hook decisions are logged only
  • enqueue_pass() is synchronous (blocks until work_queue.join())
"""

import logging
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from config import Config
from crypto import CryptoEngine
from integrity import compute_chunk_hash
from pacing import AdaptivePacingController
from protocol import PacketType, build_data_payload, build_packet
from transport import UDPTransport
from window import WindowController

logger = logging.getLogger(__name__)

# ── Sentinel used to signal worker threads to exit ────────────────────────────
_STOP = object()

# ── Windows WSAENOBUFS error code ─────────────────────────────────────────────
_WSAENOBUFS = 10055


# ── Public data types ─────────────────────────────────────────────────────────

@dataclass
class ScalingDecision:
    """
    Advisory decision returned by a ScalingHook.

    requested_streams=None  → no change requested
    requested_streams=N     → advisory request to resize to N streams
    reason                  → human-readable explanation
    """
    requested_streams: Optional[int] = None
    reason: str = ""


@dataclass
class StreamStats:
    """Per-stream statistics collected after stop()."""
    stream_id: int
    sent: int = 0
    nobufs: int = 0
    elapsed_s: float = 0.0


# Type alias for the scaling hook callable
ScalingHook = Callable[["StreamManager"], ScalingDecision]


# ── StreamManager ─────────────────────────────────────────────────────────────

class StreamManager:
    """
    Manages a fixed pool of UDP stream worker threads for a single file
    transfer session.

    Parameters
    ──────────
    config          : Config instance (chunk_size, etc.)
    pacing          : AdaptivePacingController shared with the caller
    data_transports : list of pre-created UDPTransport objects (one per stream)
    dest_host       : destination IP/hostname for data packets
    data_base_port  : first destination port; stream i sends to data_base_port+i
    filepath        : absolute path to the file being sent
    session_id      : 16-byte session identifier for packet headers
    crypto          : CryptoEngine instance (may be disabled)
    rate_limiter    : optional RateLimiter; acquire_send() called before each send
    """

    def __init__(
        self,
        config: Config,
        pacing: AdaptivePacingController,
        data_transports: List[UDPTransport],
        dest_host: str,
        data_base_port: int,
        filepath: str,
        session_id: bytes,
        crypto: CryptoEngine,
        rate_limiter=None,
        window: Optional[WindowController] = None,
    ) -> None:
        if not data_transports:
            raise ValueError("data_transports must contain at least one transport")

        self._config         = config
        self._pacing         = pacing
        self._transports     = list(data_transports)
        self._dest_host      = dest_host
        self._data_base_port = data_base_port
        self._filepath       = filepath
        self._session_id     = session_id
        self._crypto         = crypto
        self._rate_limiter   = rate_limiter
        self._window         = window

        n = len(self._transports)

        # Live counters — written by worker threads, read for display
        self._live_sent:   List[int] = [0] * n
        self._live_nobufs: List[int] = [0] * n

        # Final stats — written once per worker on exit
        self._stats: List[StreamStats] = [StreamStats(stream_id=i) for i in range(n)]

        # Work queue — filled by enqueue_pass(), drained by workers
        self._work_queue: queue.Queue = queue.Queue()

        # Lifecycle
        self._started      = False
        self._stopped      = False
        self._stop_event   = threading.Event()
        self._threads:     List[threading.Thread] = []
        self._probe_thread: Optional[threading.Thread] = None

        # Scaling hook (advisory only)
        self._hook:              Optional[ScalingHook] = None
        self._probe_interval_s:  float = 5.0

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def num_streams(self) -> int:
        return len(self._transports)

    @property
    def live_sent(self) -> List[int]:
        """Snapshot copy of per-stream sent counters (no lock — display use only)."""
        return list(self._live_sent)

    @property
    def live_nobufs(self) -> List[int]:
        """Snapshot copy of per-stream nobufs counters (no lock — display use only)."""
        return list(self._live_nobufs)

    @property
    def loss_rate(self) -> float:
        """Global nobufs / (sent + nobufs).  Returns 0.0 if no attempts yet."""
        total_sent   = sum(self._live_sent)
        total_nobufs = sum(self._live_nobufs)
        attempts = total_sent + total_nobufs
        if attempts == 0:
            return 0.0
        return total_nobufs / attempts

    # ── Public interface ──────────────────────────────────────────────────────

    def set_scaling_hook(
        self,
        hook: ScalingHook,
        probe_interval_s: float = 5.0,
    ) -> None:
        """
        Register an advisory scaling hook.

        The hook is called every probe_interval_s by a background probe thread
        (started alongside workers when start() is called).  Decisions are
        logged but NOT acted upon in Phase 3 — live stream resize is reserved
        for a future phase.

        Must be called before start().
        """
        self._hook             = hook
        self._probe_interval_s = max(0.1, float(probe_interval_s))
        logger.info(
            "StreamManager: scaling hook registered  "
            "interval=%.1fs  "
            "[Phase 3: advisory-only — no live resize will occur]",
            self._probe_interval_s,
        )

    def start(self) -> None:
        """
        Start all stream worker threads.

        Raises RuntimeError if called more than once.
        """
        if self._started:
            raise RuntimeError("StreamManager.start() called more than once")
        self._started = True

        for i, transport in enumerate(self._transports):
            t = threading.Thread(
                target=self._worker,
                args=(i, transport),
                name=f"stream-worker-{i}",
                daemon=True,
            )
            t.start()
            self._threads.append(t)

        logger.info(
            "StreamManager: started %d stream worker thread(s)", self.num_streams
        )

        if self._hook is not None:
            self._probe_thread = threading.Thread(
                target=self._scaling_probe_loop,
                name="stream-scaling-probe",
                daemon=True,
            )
            self._probe_thread.start()
            logger.debug("StreamManager: scaling probe thread started")

    def enqueue_pass(
        self,
        chunk_ids: List[int],
        label: str = "Pass",
    ) -> float:
        """
        Distribute chunk_ids across worker threads and wait for completion.

        Each chunk_id is placed on the shared work_queue exactly once.
        Workers pull from the queue concurrently.

        Returns elapsed wall-clock seconds for the pass.
        """
        chunk_size = self._config.chunk_size
        logger.info(
            "StreamManager [%s]: enqueueing %d chunk(s)  streams=%d  chunk_size=%d B",
            label, len(chunk_ids), self.num_streams, chunk_size,
        )

        t0 = time.monotonic()

        for cid in chunk_ids:
            self._work_queue.put(cid)

        self._work_queue.join()

        elapsed = time.monotonic() - t0
        total_bytes = len(chunk_ids) * chunk_size
        rate_mbs = (total_bytes / elapsed / 1_048_576) if elapsed > 0 else 0.0

        logger.info(
            "StreamManager [%s]: done  %d chunk(s)  %.3f s  ~%.1f MB/s",
            label, len(chunk_ids), elapsed, rate_mbs,
        )
        return elapsed

    def stop(self) -> List[StreamStats]:
        """
        Signal all worker threads to exit and wait for them to finish.

        Returns a list of StreamStats (one per stream) with final counters.
        Idempotent: subsequent calls return the already-computed stats immediately.
        """
        if self._stopped:
            return list(self._stats)
        self._stopped = True

        self._stop_event.set()

        # Unblock workers waiting on the queue
        self._work_queue.put(_STOP)

        for t in self._threads:
            t.join()

        if self._probe_thread is not None:
            self._probe_thread.join(timeout=self._probe_interval_s + 1.0)

        logger.info(
            "StreamManager: all %d worker(s) stopped  "
            "total_sent=%d  total_nobufs=%d",
            self.num_streams,
            sum(s.sent for s in self._stats),
            sum(s.nobufs for s in self._stats),
        )
        return list(self._stats)

    # ── Private — worker ──────────────────────────────────────────────────────

    def _worker(self, stream_id: int, transport: UDPTransport) -> None:
        """
        Stream worker loop.

        Opens the source file for reading, then continuously pulls chunk IDs
        from the shared work_queue and sends each as a DATA packet.

        Stops when the _STOP sentinel is dequeued; re-puts the sentinel so
        sibling workers also see it (fan-out stop pattern).
        """
        chunk_size   = self._config.chunk_size
        dest_addr    = (self._dest_host, self._data_base_port + stream_id)
        local_sent   = 0
        local_nobufs = 0
        t0           = time.monotonic()

        try:
            with open(self._filepath, "rb") as fh:
                while True:
                    item = self._work_queue.get()

                    if item is _STOP:
                        # Fan-out: put sentinel back for other workers
                        self._work_queue.put(_STOP)
                        self._work_queue.task_done()
                        break

                    chunk_id = item

                    # ── Window gate (Phase 4) ─────────────────────────────────
                    # acquire() BEFORE reading or sending; release happens ONLY
                    # in the sender's SACK handler — never here.
                    if self._window is not None:
                        _stall_log_t = time.monotonic()
                        while not self._stop_event.is_set():
                            if self._window.acquire(timeout=0.5):
                                break
                            # Log a stall warning every 5 s while blocked
                            if time.monotonic() - _stall_log_t >= 5.0:
                                logger.warning(
                                    "stream %d: window STALL — in_flight=%d/%d  "
                                    "waiting for SACK …",
                                    stream_id,
                                    self._window.in_flight,
                                    self._window.max_window,
                                )
                                _stall_log_t = time.monotonic()
                        else:
                            # stop_event fired while waiting — abandon this chunk
                            self._work_queue.task_done()
                            break

                    try:
                        # ── Read chunk ────────────────────────────────────────
                        byte_offset = chunk_id * chunk_size
                        fh.seek(byte_offset)
                        data = fh.read(chunk_size)

                        if not data:
                            logger.warning(
                                "stream %d: empty read at offset %d (chunk %d) — skipping",
                                stream_id, byte_offset, chunk_id,
                            )
                            continue

                        # ── Integrity checksum (over plaintext) ───────────────
                        checksum = compute_chunk_hash(data)

                        # ── Encrypt (if enabled) ──────────────────────────────
                        nonce, enc_data = self._crypto.encrypt(data)
                        if self._crypto.is_enabled:
                            payload_data = nonce + enc_data
                        else:
                            payload_data = enc_data  # plaintext (nonce is b"")

                        # ── Build packet ──────────────────────────────────────
                        data_payload = build_data_payload(
                            chunk_id,
                            byte_offset,
                            len(payload_data),  # ciphertext (or plaintext) size — what is actually written into the packet
                            checksum,
                            payload_data,
                        )
                        pkt = build_packet(
                            PacketType.DATA,
                            self._session_id,
                            chunk_id,
                            data_payload,
                        )

                        # ── Rate limiting ─────────────────────────────────────
                        if self._rate_limiter is not None:
                            self._rate_limiter.acquire_send(len(pkt))

                        # ── Send loop ─────────────────────────────────────────
                        while True:
                            try:
                                transport.send(pkt, dest_addr)
                                # Success
                                local_sent           += 1
                                self._live_sent[stream_id] = local_sent
                                self._pacing.record_success(stream_id)
                                delay = self._pacing.delay_s
                                if delay > 0:
                                    time.sleep(delay)
                                break

                            except OSError as exc:
                                if getattr(exc, "winerror", None) == _WSAENOBUFS:
                                    local_nobufs                    += 1
                                    self._live_nobufs[stream_id]    = local_nobufs
                                    self._pacing.record_loss(stream_id)
                                    delay = self._pacing.delay_s
                                    if delay > 0:
                                        time.sleep(delay)
                                    # Retry same chunk
                                else:
                                    raise

                    finally:
                        self._work_queue.task_done()

        except Exception:
            logger.exception("stream %d: unhandled exception", stream_id)
        finally:
            elapsed = time.monotonic() - t0
            self._stats[stream_id] = StreamStats(
                stream_id=stream_id,
                sent=local_sent,
                nobufs=local_nobufs,
                elapsed_s=elapsed,
            )
            logger.info(
                "stream %d: exiting  sent=%d  nobufs=%d  elapsed=%.3fs",
                stream_id, local_sent, local_nobufs, elapsed,
            )

    # ── Private — scaling probe ───────────────────────────────────────────────

    def _scaling_probe_loop(self) -> None:
        """
        Background thread that calls the ScalingHook periodically.

        In Phase 3 all decisions are advisory only — no live stream resize is
        performed.  The decision is logged so that future phases can act on it.
        """
        logger.debug(
            "scaling probe: starting  interval=%.1fs  "
            "[Phase 3: advisory log only]",
            self._probe_interval_s,
        )

        while not self._stop_event.wait(timeout=self._probe_interval_s):
            if self._hook is None:
                break
            try:
                decision = self._hook(self)
            except Exception:
                logger.exception("scaling probe: hook raised an exception")
                continue

            if decision.requested_streams is not None:
                logger.info(
                    "scaling probe: advisory decision — requested_streams=%d  "
                    "reason=%r  "
                    "[Phase 3: no live resize performed]",
                    decision.requested_streams,
                    decision.reason,
                )
            else:
                logger.debug(
                    "scaling probe: no change requested  reason=%r",
                    decision.reason,
                )

        logger.debug("scaling probe: exiting")
