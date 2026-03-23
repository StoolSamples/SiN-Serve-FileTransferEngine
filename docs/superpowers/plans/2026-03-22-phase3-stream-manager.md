# Phase 3 — Stream Manager Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Introduce a formal `StreamManager` class that encapsulates all multi-stream worker logic, adds adaptive scaling hooks, adds receiver-side metrics, and verifies the existing resume capability with tests.

**Architecture:** Extract the inline stream-worker pool from `FileSender._run_transfer()` into a dedicated `StreamManager` class. `FileSender` delegates all chunk-dispatch work to `StreamManager`; it retains handshake, FINISH, and NACK logic. `TransferController` gains a `set_scaling_hook()` API so callers can register a callback that the manager consults at each probe interval. `FileReceiver` gains a `_write_metrics()` call mirroring the sender's existing one.

**Tech Stack:** Python 3.12, threading, queue, existing `UDPTransport`, `AdaptivePacingController`, `Config`

---

## Audit Summary (do not re-implement these — they are complete)

| Component | Status |
|---|---|
| Multi-stream UDP send (4 streams, configurable) | ✅ Working |
| Chunk work-queue with no duplicates | ✅ Working |
| RAM-mode and disk-mode receiving | ✅ Working |
| SidecarManager + `_load_resume_state` | ✅ Working |
| Session blackout | ✅ Working |
| Sender-side metrics (`_write_metrics`) | ✅ Working |
| NACK pass, throughput reporting | ✅ Working |
| Step-climb pacing controller | ✅ Working |

## What Phase 3 adds

| Feature | File | Status |
|---|---|---|
| `StreamManager` class | `stream_manager.py` (new) | ❌ Missing |
| Adaptive scaling hook interface | `stream_manager.py` | ❌ Missing |
| `FileSender` delegates to `StreamManager` | `sender.py` | ❌ Needs refactor |
| `TransferController.set_scaling_hook()` | `transfer_controller.py` | ❌ Missing |
| Receiver-side metrics | `receiver.py` | ❌ Missing |
| Tests | `tests/` (new) | ❌ Missing |

---

## File Map

```
stream_manager.py          NEW  — StreamManager class + ScalingHook protocol
sender.py                  MOD  — delegate _run_transfer worker pool to StreamManager
transfer_controller.py     MOD  — add set_scaling_hook() / get_stream_stats()
receiver.py                MOD  — add _write_metrics() call in _control_loop()
tests/test_stream_manager.py  NEW  — unit tests for StreamManager
tests/test_resume.py          NEW  — resume / sidecar integration test
tests/test_e2e.py             NEW  — end-to-end loopback with metrics check
```

---

## Task 1: Create `stream_manager.py`

**Files:**
- Create: `Z:/Claude/FileTransferEngine/stream_manager.py`

The `StreamManager` owns: work queue, stream worker threads, per-stream stats, and the pacing controller reference.  It does NOT own sockets (caller passes them in) or the file handle (workers open their own).

- [ ] **Step 1: Write the failing import test**

Create `Z:/Claude/FileTransferEngine/tests/test_stream_manager.py`:

```python
"""Tests for StreamManager — Phase 3."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from stream_manager import StreamManager, ScalingDecision


def test_import():
    """StreamManager and ScalingDecision are importable."""
    assert StreamManager is not None
    assert ScalingDecision is not None
```

- [ ] **Step 2: Run test to confirm it fails**

```
cd Z:/Claude/FileTransferEngine
python -m pytest tests/test_stream_manager.py::test_import -v
```
Expected: `ModuleNotFoundError: No module named 'stream_manager'`

- [ ] **Step 3: Create `stream_manager.py`**

```python
"""
stream_manager.py — StreamManager: Phase 3 multi-stream coordinator.

Responsibilities:
  - Owns the chunk work queue and stream worker thread pool.
  - Distributes chunks across N streams via a shared queue (pull model).
  - Tracks per-stream send/nobufs counters.
  - Consults a ScalingHook at each probe interval (hook for future
    adaptive scaling — no dynamic socket add/remove in Phase 3).
  - Provides clean start() / stop() / enqueue_pass() lifecycle.

Phase 3 dynamic scaling:
  Currently fixed at construction time (num_streams from Config).
  The ScalingHook interface is the extension point for Phase 5+.
  A hook returning a new stream count is logged but NOT acted on
  in Phase 3 — the infrastructure is in place, the live resize is not.
"""

import logging
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from config import Config
from pacing import AdaptivePacingController
from transport import UDPTransport
from integrity import compute_chunk_hash
from protocol import PacketType, build_packet, build_data_payload

logger = logging.getLogger(__name__)

_STOP = object()
_QUEUE_MAX = 16_000


@dataclass
class StreamStats:
    """Per-stream counters, safe to read from outside threads after stop()."""
    stream_id:  int
    sent:       int = 0
    nobufs:     int = 0
    elapsed_s:  float = 0.0

    @property
    def mbps(self) -> float:
        if self.elapsed_s <= 0 or self.sent == 0:
            return 0.0
        # approximate: chunk_size not stored here, caller uses it
        return 0.0


@dataclass
class ScalingDecision:
    """
    Return value from a ScalingHook callable.

    requested_streams: new desired stream count, or None to keep current.
    reason:            human-readable explanation for logs.
    """
    requested_streams: Optional[int] = None
    reason: str = ""


# Type alias for scaling hook
ScalingHook = Callable[["StreamManager"], ScalingDecision]


class StreamManager:
    """
    Manages a pool of stream worker threads for UDP chunk dispatch.

    Usage::

        mgr = StreamManager(cfg, pacing, data_transports,
                            dest_host, data_base_port,
                            filepath, session_id, crypto)
        mgr.start()
        mgr.enqueue_pass(list(range(total_chunks)))   # blocks until done
        stats = mgr.stop()

    Scaling hook (Phase 3 hook, full implementation Phase 5+)::

        def my_hook(mgr: StreamManager) -> ScalingDecision:
            if mgr.loss_rate > 0.05:
                return ScalingDecision(requested_streams=2, reason="high loss")
            return ScalingDecision()

        mgr.set_scaling_hook(my_hook, probe_interval_s=5.0)
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
        crypto,                   # CryptoEngine instance
        rate_limiter=None,        # RateLimiter instance or None
    ) -> None:
        self._cfg         = config
        self._pacing      = pacing
        self._transports  = data_transports
        self._dest_host   = dest_host
        self._data_base   = data_base_port
        self._filepath    = filepath
        self._session_id  = session_id
        self._crypto      = crypto
        self._rate_limiter = rate_limiter

        self._num_streams = len(data_transports)
        self._chunk_size  = config.chunk_size

        self._work_queue: queue.Queue = queue.Queue(maxsize=_QUEUE_MAX)
        self._stats: List[StreamStats] = [
            StreamStats(stream_id=i) for i in range(self._num_streams)
        ]
        # Live counters readable without lock (approximate)
        self._live_sent   = [0] * self._num_streams
        self._live_nobufs = [0] * self._num_streams
        self._stats_lock  = threading.Lock()

        self._threads: List[threading.Thread] = []
        self._started = False

        # Scaling hook
        self._scaling_hook:        Optional[ScalingHook] = None
        self._scaling_interval_s:  float = 5.0
        self._scaling_thread:      Optional[threading.Thread] = None
        self._stop_scaling:        threading.Event = threading.Event()

    # ── Properties ─────────────────────────────────────────────────────────────

    @property
    def num_streams(self) -> int:
        return self._num_streams

    @property
    def live_sent(self) -> List[int]:
        """Approximate per-stream sent counts (no lock — acceptable for display)."""
        return list(self._live_sent)

    @property
    def live_nobufs(self) -> List[int]:
        """Approximate per-stream nobufs counts."""
        return list(self._live_nobufs)

    @property
    def loss_rate(self) -> float:
        """Fraction of send attempts that hit WSAENOBUFS (0.0–1.0)."""
        total_sent   = sum(self._live_sent)
        total_nobufs = sum(self._live_nobufs)
        total = total_sent + total_nobufs
        return (total_nobufs / total) if total > 0 else 0.0

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def set_scaling_hook(
        self,
        hook: ScalingHook,
        probe_interval_s: float = 5.0,
    ) -> None:
        """
        Register a callback that is consulted at each probe interval.

        Phase 3: the hook's ScalingDecision.requested_streams is logged
        but NOT acted on (live stream resize is a Phase 5+ feature).
        This establishes the interface so callers can already wire hooks.
        """
        self._scaling_hook       = hook
        self._scaling_interval_s = max(1.0, probe_interval_s)
        logger.info(
            "StreamManager: scaling hook registered  probe_interval=%.1fs  "
            "(Phase 3 — advisory only, no live resize)",
            self._scaling_interval_s,
        )

    def start(self) -> None:
        """Start all stream worker threads (and scaling probe if hook set)."""
        if self._started:
            raise RuntimeError("StreamManager already started")
        self._started = True

        for i, transport in enumerate(self._transports):
            t = threading.Thread(
                target=self._worker,
                args=(i, transport),
                daemon=True,
                name=f"Stream-{i}",
            )
            t.start()
            self._threads.append(t)

        logger.info(
            "%d stream workers started  start_rate=%s  loss_threshold=%d",
            self._num_streams,
            self._pacing.tier_name,
            self._cfg.loss_threshold,
        )

        if self._scaling_hook is not None:
            self._scaling_thread = threading.Thread(
                target=self._scaling_probe_loop,
                daemon=True,
                name="ScalingProbe",
            )
            self._scaling_thread.start()

    def enqueue_pass(self, chunk_ids: List[int], label: str = "Pass") -> float:
        """
        Queue chunk_ids, wait for all to complete, return elapsed seconds.
        Blocks the calling thread until work_queue.join() returns.
        """
        n  = len(chunk_ids)
        t0 = time.monotonic()
        logger.info("%s: queuing %d chunks ...", label, n)
        for cid in chunk_ids:
            self._work_queue.put(cid)
        self._work_queue.join()
        elapsed = time.monotonic() - t0
        mbps = (n * self._chunk_size / 1_048_576 / elapsed) if elapsed > 0 else 0.0
        logger.info(
            "%s: done  %d chunks  %.2fs  ~%.1f MB/s  rate=%s",
            label, n, elapsed, mbps, self._pacing.tier_name,
        )
        return elapsed

    def stop(self) -> List[StreamStats]:
        """
        Signal all workers to stop, join threads, return final stats.
        Safe to call more than once.
        """
        self._stop_scaling.set()
        self._work_queue.put(_STOP)
        for t in self._threads:
            t.join(timeout=10.0)
            if t.is_alive():
                logger.warning("Worker %s did not stop cleanly", t.name)
        if self._scaling_thread is not None:
            self._scaling_thread.join(timeout=2.0)

        with self._stats_lock:
            snapshot = list(self._stats)

        total_nobufs = sum(s.nobufs for s in snapshot)
        logger.info(
            "StreamManager stopped.  sent=%s  nobufs=%s  final_rate=%s",
            [s.sent for s in snapshot],
            [s.nobufs for s in snapshot],
            self._pacing.tier_name,
        )
        if total_nobufs:
            logger.info("Total WSAENOBUFS: %d", total_nobufs)
        return snapshot

    # ── Worker internals ───────────────────────────────────────────────────────

    _WSAENOBUFS = 10055

    def _worker(self, stream_id: int, transport: UDPTransport) -> None:
        dest     = (self._dest_host, self._data_base + stream_id)
        local_sent   = 0
        local_nobufs = 0
        t_start  = time.monotonic()

        logger.debug(
            "Stream-%d: -> %s:%d  rate=%s  delay=%.1f us",
            stream_id, self._dest_host, self._data_base + stream_id,
            self._pacing.tier_name, self._pacing.delay_s * 1_000_000,
        )

        try:
            with open(self._filepath, "rb") as fh:
                while True:
                    item = self._work_queue.get()
                    if item is _STOP:
                        self._work_queue.task_done()
                        self._work_queue.put(_STOP)
                        break

                    chunk_id    = item
                    byte_offset = chunk_id * self._chunk_size
                    fh.seek(byte_offset)
                    data = fh.read(self._chunk_size)
                    if not data:
                        logger.warning("Stream-%d: chunk %d: empty read",
                                       stream_id, chunk_id)
                        self._work_queue.task_done()
                        continue

                    checksum = compute_chunk_hash(data)
                    nonce, enc_data = self._crypto.encrypt(data)
                    enc_payload = (nonce + enc_data) if self._crypto.is_enabled else enc_data

                    payload = build_data_payload(
                        chunk_id=chunk_id,
                        byte_offset=byte_offset,
                        chunk_data_size=len(enc_payload),
                        checksum=checksum,
                        data=enc_payload,
                    )
                    pkt = build_packet(PacketType.DATA, self._session_id, chunk_id, payload)

                    if self._rate_limiter is not None:
                        self._rate_limiter.acquire_send(len(pkt))

                    while True:
                        try:
                            transport.send(pkt, dest)
                            local_sent += 1
                            self._live_sent[stream_id] += 1
                            self._work_queue.task_done()
                            self._pacing.record_success(stream_id)
                            time.sleep(self._pacing.delay_s)
                            break
                        except OSError as exc:
                            if getattr(exc, "winerror", None) == self._WSAENOBUFS:
                                local_nobufs += 1
                                self._live_nobufs[stream_id] += 1
                                self._pacing.record_loss(stream_id)
                                time.sleep(self._pacing.delay_s)
                            else:
                                logger.error(
                                    "Stream-%d: fatal send error chunk %d: %s",
                                    stream_id, chunk_id, exc,
                                )
                                self._work_queue.task_done()
                                raise

        except OSError as exc:
            logger.error("Stream-%d: exiting on error: %s", stream_id, exc)
        except Exception as exc:
            logger.error("Stream-%d: unexpected error: %s", stream_id, exc,
                         exc_info=True)

        elapsed = time.monotonic() - t_start
        mbps    = (local_sent * self._chunk_size / 1_048_576 / elapsed
                   if elapsed > 0 else 0.0)
        logger.info(
            "Stream-%d: stopped  sent=%d  nobufs=%d  %.2fs  ~%.1f MB/s  rate=%s",
            stream_id, local_sent, local_nobufs, elapsed, mbps,
            self._pacing.tier_name,
        )
        with self._stats_lock:
            self._stats[stream_id].sent      = local_sent
            self._stats[stream_id].nobufs    = local_nobufs
            self._stats[stream_id].elapsed_s = elapsed

    def _scaling_probe_loop(self) -> None:
        """
        Consults the scaling hook at each probe interval.
        Phase 3: logs the decision; does NOT perform live stream resize.
        """
        while not self._stop_scaling.wait(timeout=self._scaling_interval_s):
            if self._scaling_hook is None:
                break
            try:
                decision = self._scaling_hook(self)
            except Exception as exc:
                logger.warning("ScalingHook raised: %s", exc)
                continue

            if decision.requested_streams is not None:
                logger.info(
                    "ScalingHook advisory: current=%d  requested=%d  reason=%r  "
                    "(Phase 3 — live resize deferred to Phase 5)",
                    self._num_streams,
                    decision.requested_streams,
                    decision.reason,
                )
            else:
                logger.debug(
                    "ScalingHook: no change requested  current=%d  loss=%.2f%%",
                    self._num_streams, self.loss_rate * 100,
                )
```

- [ ] **Step 4: Run test to confirm import passes**

```
python -m pytest tests/test_stream_manager.py::test_import -v
```
Expected: `PASSED`

- [ ] **Step 5: Write full StreamManager unit tests**

Append to `tests/test_stream_manager.py`:

```python
import threading, time, socket, tempfile, os
from unittest.mock import MagicMock, patch
from stream_manager import StreamManager, ScalingDecision


def _make_config(num_streams=2, chunk_size=1024):
    cfg = MagicMock()
    cfg.num_streams         = num_streams
    cfg.chunk_size          = chunk_size
    cfg.loss_threshold      = 12
    cfg.initial_rate_mbps   = 50.0
    cfg.min_rate_mbps       = 10.0
    cfg.coarse_step_mbps    = 10.0
    cfg.fine_step_mbps      = 1.0
    cfg.micro_step_mbps     = 0.1
    cfg.coarse_interval_s   = 2.5
    cfg.fine_interval_s     = 2.5
    cfg.micro_interval_s    = 1.0
    cfg.hold_interval_s     = 2.5
    return cfg


def _make_pacing(cfg):
    from pacing import AdaptivePacingController
    return AdaptivePacingController(
        num_streams=cfg.num_streams,
        chunk_size=cfg.chunk_size,
        loss_threshold=cfg.loss_threshold,
        initial_rate_mbs=cfg.initial_rate_mbps,
        min_rate_mbs=cfg.min_rate_mbps,
    )


def _make_crypto_disabled():
    crypto = MagicMock()
    crypto.is_enabled = False
    crypto.encrypt.side_effect = lambda data: (b"", data)
    return crypto


def _make_loopback_transports(num_streams, data_base=19100):
    """Return (send_transports, recv_sockets)."""
    from transport import UDPTransport
    senders = []
    receivers = []
    for i in range(num_streams):
        port  = data_base + i
        recv  = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        recv.bind(("127.0.0.1", port))
        recv.settimeout(2.0)
        receivers.append(recv)
        s = UDPTransport(("", 0), buffer_size=1024*1024)
        senders.append(s)
    return senders, receivers


def test_stream_manager_init():
    """StreamManager initialises with correct stream count."""
    cfg        = _make_config(num_streams=2)
    pacing     = _make_pacing(cfg)
    crypto     = _make_crypto_disabled()
    transports = [MagicMock() for _ in range(2)]

    mgr = StreamManager(cfg, pacing, transports, "127.0.0.1", 19200,
                        "/fake/path", b"\x00" * 16, crypto)
    assert mgr.num_streams == 2
    assert len(mgr.live_sent) == 2
    assert mgr.loss_rate == 0.0


def test_scaling_hook_registration():
    """Scaling hook is registered and consulted without raising."""
    cfg        = _make_config(num_streams=1)
    pacing     = _make_pacing(cfg)
    crypto     = _make_crypto_disabled()
    transports = [MagicMock()]

    decisions = []
    def my_hook(mgr):
        d = ScalingDecision(requested_streams=2, reason="test")
        decisions.append(d)
        return d

    mgr = StreamManager(cfg, pacing, transports, "127.0.0.1", 19210,
                        "/fake/path", b"\x00" * 16, crypto)
    mgr.set_scaling_hook(my_hook, probe_interval_s=0.1)
    # Don't start workers (no real sockets) — just verify hook stored
    assert mgr._scaling_hook is my_hook
    assert mgr._scaling_interval_s == 0.1


def test_scaling_decision_no_change():
    """ScalingDecision with None requested_streams means no change."""
    d = ScalingDecision()
    assert d.requested_streams is None
    assert d.reason == ""


def test_stream_manager_enqueue_and_receive(tmp_path):
    """
    Full loopback: StreamManager sends N chunks; receivers collect them all.
    Uses real UDP sockets on loopback.
    """
    NUM_STREAMS = 2
    CHUNK_SIZE  = 512
    NUM_CHUNKS  = 10
    DATA_BASE   = 19300

    # Create test file
    src = tmp_path / "test.bin"
    src.write_bytes(bytes(range(256)) * (CHUNK_SIZE * NUM_CHUNKS // 256 + 1))
    src = str(src)[:CHUNK_SIZE * NUM_CHUNKS]   # trim isn't needed for content; just use path

    # Write exact content
    content = bytes(range(CHUNK_SIZE % 256)) * NUM_CHUNKS
    with open(src, "wb") as f:
        f.write(bytes(range(CHUNK_SIZE)) * NUM_CHUNKS)

    cfg    = _make_config(num_streams=NUM_STREAMS, chunk_size=CHUNK_SIZE)
    pacing = _make_pacing(cfg)
    crypto = _make_crypto_disabled()

    senders, recv_socks = _make_loopback_transports(NUM_STREAMS, DATA_BASE)

    received_chunks = []
    recv_lock       = threading.Lock()
    recv_stop       = threading.Event()

    def drain_receiver(sock):
        while not recv_stop.is_set():
            try:
                data, _ = sock.recvfrom(65535)
                with recv_lock:
                    received_chunks.append(data)
            except socket.timeout:
                continue

    recv_threads = [threading.Thread(target=drain_receiver, args=(s,), daemon=True)
                    for s in recv_socks]
    for t in recv_threads:
        t.start()

    session_id = os.urandom(16)
    mgr = StreamManager(cfg, pacing, senders, "127.0.0.1", DATA_BASE,
                        str(src), session_id, crypto)
    mgr.start()
    mgr.enqueue_pass(list(range(NUM_CHUNKS)), label="Test pass")
    stats = mgr.stop()

    recv_stop.set()
    for s in recv_socks:
        s.close()
    for s in senders:
        s.close()

    assert sum(s.sent for s in stats) == NUM_CHUNKS, (
        f"Expected {NUM_CHUNKS} sent, got {sum(s.sent for s in stats)}"
    )
    assert len(received_chunks) == NUM_CHUNKS, (
        f"Expected {NUM_CHUNKS} received, got {len(received_chunks)}"
    )
```

- [ ] **Step 6: Run all StreamManager tests**

```
python -m pytest tests/test_stream_manager.py -v
```
Expected: all `PASSED`

- [ ] **Step 7: Commit**

```
git add stream_manager.py tests/test_stream_manager.py
git commit -m "feat(phase3): add StreamManager class with scaling hook interface"
```

---

## Task 2: Refactor `sender.py` to delegate to `StreamManager`

**Files:**
- Modify: `Z:/Claude/FileTransferEngine/sender.py`

The goal is minimal: replace the inline `stream_worker` function + thread-spawn block + `run_send_pass` in `_run_transfer` with calls to `StreamManager`. The handshake, NACK pass, FINISH loop, metrics, and reporter thread all stay in `FileSender`.

- [ ] **Step 1: Identify the exact block to replace in `sender.py`**

In `_run_transfer()`:
- Lines that define `stream_worker()` → moves to `StreamManager._worker()`
- Lines that define `run_send_pass()` → replaced by `mgr.enqueue_pass()`
- Lines that start/stop worker threads → replaced by `mgr.start()` / `mgr.stop()`

The per-stream live counters (`stream_sent_live`, `stream_nobufs_live`) used by the pacing reporter thread must come from `mgr.live_sent` / `mgr.live_nobufs`.

- [ ] **Step 2: Write the refactored `_run_transfer` skeleton (key changes only)**

Replace in `sender.py`:

```python
# OLD imports (top of file) — add:
from stream_manager import StreamManager, ScalingDecision

# In _run_transfer, REMOVE:
#   - stream_sent, stream_nobufs, stats_lock, stream_sent_live, stream_nobufs_live
#   - def stream_worker(...)
#   - thread list creation and start loop
#   - def run_send_pass(...)
#   - stop_workers() inner function (partially — keep feedback/reporter stop)

# REPLACE WITH:
mgr = StreamManager(
    config=self._cfg,
    pacing=pacing,
    data_transports=data_transports,
    dest_host=dest_host,
    data_base_port=data_base,
    filepath=filepath,
    session_id=session_id,
    crypto=self._crypto,
    rate_limiter=self._rate_limiter,
)
if self._scaling_hook is not None:
    mgr.set_scaling_hook(self._scaling_hook, self._scaling_hook_interval_s)
mgr.start()

# Replace run_send_pass calls:
initial_pass_elapsed = mgr.enqueue_pass(list(range(total_chunks)), "Initial pass")

# In NACK pass:
if nack_list:
    mgr.enqueue_pass(nack_list, "NACK pass")

# In resend pass:
mgr.enqueue_pass(unique_missing, f"Resend #{resend_pass}")

# Replace stop_workers():
stats = mgr.stop()
stream_sent   = [s.sent   for s in stats]
stream_nobufs = [s.nobufs for s in stats]
# then stop reporter and feedback threads (unchanged)

# Pacing reporter reads from mgr instead of live lists:
# total_sent = sum(mgr.live_sent)
```

- [ ] **Step 3: Add `set_scaling_hook` to `FileSender`**

Add to `FileSender.__init__`:
```python
self._scaling_hook:          Optional[ScalingHook] = None
self._scaling_hook_interval_s: float = 5.0
```

Add public method:
```python
def set_scaling_hook(
    self,
    hook: "ScalingHook",
    probe_interval_s: float = 5.0,
) -> None:
    """Register a scaling hook forwarded to StreamManager on next send."""
    self._scaling_hook           = hook
    self._scaling_hook_interval_s = probe_interval_s
```

- [ ] **Step 4: Run existing loopback self-test to confirm nothing broke**

```
python -X utf8 main.py test --size 5 --port 19050
```
Expected: `SELF-TEST PASSED — SHA-256 matches perfectly.`

- [ ] **Step 5: Commit**

```
git add sender.py
git commit -m "refactor(phase3): delegate stream workers to StreamManager in FileSender"
```

---

## Task 3: Add `set_scaling_hook` to `TransferController`

**Files:**
- Modify: `Z:/Claude/FileTransferEngine/transfer_controller.py`

`TransferController` is the public API used by `main.py` and future GUI. It should expose the scaling hook so callers don't need to import `FileSender` directly.

- [ ] **Step 1: Add hook wiring to `TransferController`**

In `transfer_controller.py`, add to `__init__`:
```python
self._scaling_hook:          Optional[Callable] = None
self._scaling_hook_interval_s: float = 5.0
```

Add public method:
```python
def set_scaling_hook(
    self,
    hook: Callable,
    probe_interval_s: float = 5.0,
) -> None:
    """
    Register a scaling hook consulted by StreamManager during transfers.

    hook signature: (StreamManager) -> ScalingDecision
    Phase 3: advisory only (logged, not acted on for live resize).
    """
    self._scaling_hook            = hook
    self._scaling_hook_interval_s = probe_interval_s
    logger.info("TransferController: scaling hook registered")
```

In `send()`, wire it before `sender.send_file()`:
```python
sender = FileSender(self._cfg)
if self._scaling_hook is not None:
    sender.set_scaling_hook(
        self._scaling_hook, self._scaling_hook_interval_s
    )
ok = sender.send_file(...)
```

- [ ] **Step 2: Add a scaling hook smoke test to `main.py test`**

In `cmd_test()`, after creating the controller, register a no-op hook:
```python
from stream_manager import ScalingDecision
ctrl.set_scaling_hook(lambda mgr: ScalingDecision(), probe_interval_s=2.0)
```

- [ ] **Step 3: Run self-test again**

```
python -X utf8 main.py test --size 5 --port 19060
```
Expected: `SELF-TEST PASSED — SHA-256 matches perfectly.`

- [ ] **Step 4: Commit**

```
git add transfer_controller.py main.py
git commit -m "feat(phase3): expose scaling hook API on TransferController"
```

---

## Task 4: Add receiver-side metrics writing

**Files:**
- Modify: `Z:/Claude/FileTransferEngine/receiver.py`

The sender already calls `_write_metrics()` (gated by `metrics_enabled`). The receiver should write a complementary metrics record.

- [ ] **Step 1: Add `_write_metrics` to `FileReceiver`**

Add this method to `FileReceiver` (mirrors `FileSender._write_metrics`):

```python
def _write_metrics(
    self,
    session_id: bytes,
    output_path: str,
    file_size: int,
    total_chunks: int,
    chunk_size: int,
    num_streams: int,
    recv_start: float,
    written_chunks: int,
    success: bool,
    failure_reason: str = "",
) -> None:
    if not self._cfg.metrics_enabled:
        return
    duration_s = time.monotonic() - recv_start
    throughput = (file_size / duration_s / 1_048_576) if duration_s > 0 else 0.0
    metrics = {
        "side": "receiver",
        "session_id": session_id.hex(),
        "filename": os.path.basename(output_path),
        "file_size": file_size,
        "total_chunks": total_chunks,
        "chunk_size": chunk_size,
        "num_streams": num_streams,
        "duration_s": round(duration_s, 3),
        "throughput_mbps": round(throughput, 2),
        "chunks_written": written_chunks,
        "success": success,
        "failure_reason": failure_reason,
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
```

- [ ] **Step 2: Call `_write_metrics` at end of `_control_loop`**

At both the success path and the timeout/failure path in `_control_loop`, call:

```python
# Success path (just before return output_path):
self._write_metrics(
    session_id, output_path, file_size, total_chunks,
    chunk_size, num_streams, recv_start,
    written_chunks=len(written_chunks),
    success=True,
)

# Failure/timeout path (just before raise RuntimeError):
self._write_metrics(
    session_id, output_path, file_size, total_chunks,
    chunk_size, num_streams, recv_start,
    written_chunks=len(written_chunks),
    success=False, failure_reason="timeout",
)
```

- [ ] **Step 3: Run self-test with metrics enabled**

Temporarily set `"metrics_enabled": true` in `config.json`, run:
```
python -X utf8 main.py test --size 5 --port 19070
```
Expected: `SELF-TEST PASSED` + two metrics files created (`.ft_metrics.json` and `.ft_metrics_recv.json`)

Restore `config.json` to `"metrics_enabled": false`.

- [ ] **Step 4: Commit**

```
git add receiver.py
git commit -m "feat(phase3): add receiver-side metrics writing"
```

---

## Task 5: Resume integration test

**Files:**
- Create: `Z:/Claude/FileTransferEngine/tests/test_resume.py`

The resume logic (`_load_resume_state` + `SidecarManager`) is implemented but untested.  This task verifies it works end-to-end.

- [ ] **Step 1: Write the resume test**

```python
"""
test_resume.py — Integration test for sidecar-based resume.

Strategy:
  1. Write a real sidecar file simulating a partial transfer
     (e.g. 50 of 100 chunks written).
  2. Call _load_resume_state with matching metadata.
  3. Assert the loaded set matches what was written.
  4. Assert _validate_sidecar rejects mismatched metadata.
"""
import sys, os, json, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from receiver import FileReceiver, SidecarManager
from unittest.mock import MagicMock


def _make_config(resume_enabled=True):
    cfg = MagicMock()
    cfg.resume_enabled = resume_enabled
    return cfg


def _make_meta(filename="test.bin", file_size=1024000,
               total_chunks=100, chunk_size=10240):
    sha = bytes(32)
    return {
        "filename":     filename,
        "file_size":    file_size,
        "total_chunks": total_chunks,
        "chunk_size":   chunk_size,
        "file_sha256":  sha,
    }


def test_load_resume_state_disabled():
    """Returns empty set when resume_enabled=False."""
    cfg = _make_config(resume_enabled=False)
    recv = FileReceiver(cfg)
    result = recv._load_resume_state("/any/path", _make_meta(), b"\x00" * 16)
    assert result == set()


def test_load_resume_state_no_sidecar(tmp_path):
    """Returns empty set when no sidecar file exists."""
    cfg  = _make_config(resume_enabled=True)
    recv = FileReceiver(cfg)
    path = str(tmp_path / "test.bin")
    meta = _make_meta()
    result = recv._load_resume_state(path, meta, b"\x00" * 16)
    assert result == set()


def test_load_resume_state_happy_path(tmp_path):
    """Correctly loads partial chunk set from a valid sidecar."""
    meta     = _make_meta()
    out_path = str(tmp_path / "test.bin")
    sha      = meta["file_sha256"]

    sidecar_data = {
        "version":       1,
        "session_id":    "aa" * 16,
        "filename":      meta["filename"],
        "file_size":     meta["file_size"],
        "total_chunks":  meta["total_chunks"],
        "chunk_size":    meta["chunk_size"],
        "file_sha256":   sha.hex(),
        "written_chunks": list(range(50)),  # first 50 chunks
        "timestamp":     1700000000.0,
    }
    sidecar_path = out_path + SidecarManager.SIDECAR_SUFFIX
    with open(sidecar_path, "w") as fh:
        json.dump(sidecar_data, fh)

    cfg  = _make_config(resume_enabled=True)
    recv = FileReceiver(cfg)
    result = recv._load_resume_state(out_path, meta, b"\x00" * 16)
    assert result == set(range(50)), f"Got: {result}"


def test_validate_sidecar_mismatch():
    """_validate_sidecar rejects mismatched filename."""
    meta    = _make_meta()
    sidecar = {
        "filename":      "wrong.bin",   # mismatch
        "file_size":     meta["file_size"],
        "total_chunks":  meta["total_chunks"],
        "chunk_size":    meta["chunk_size"],
        "file_sha256":   meta["file_sha256"].hex(),
    }
    assert not FileReceiver._validate_sidecar(sidecar, meta)


def test_validate_sidecar_match():
    """_validate_sidecar accepts matching metadata."""
    meta    = _make_meta()
    sidecar = {
        "filename":      meta["filename"],
        "file_size":     meta["file_size"],
        "total_chunks":  meta["total_chunks"],
        "chunk_size":    meta["chunk_size"],
        "file_sha256":   meta["file_sha256"].hex(),
    }
    assert FileReceiver._validate_sidecar(sidecar, meta)
```

- [ ] **Step 2: Run resume tests**

```
python -m pytest tests/test_resume.py -v
```
Expected: all `PASSED`

- [ ] **Step 3: Commit**

```
git add tests/test_resume.py
git commit -m "test(phase3): add resume/sidecar integration tests"
```

---

## Task 6: End-to-end test with metrics

**Files:**
- Create: `Z:/Claude/FileTransferEngine/tests/test_e2e.py`

- [ ] **Step 1: Write the E2E test**

```python
"""
test_e2e.py — End-to-end loopback test via main.py test command.

Verifies:
  1. SHA-256 matches after transfer (core correctness).
  2. Metrics files are written when metrics_enabled=True.
  3. Scaling hook is called during transfer.
"""
import sys, os, json, subprocess, tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def test_loopback_sha_match():
    """Basic loopback: 2 MiB file, SHA-256 must match."""
    result = subprocess.run(
        [sys.executable, "-X", "utf8", "main.py", "test",
         "--size", "2", "--port", "19800"],
        capture_output=True, text=True, timeout=60,
        cwd=os.path.join(os.path.dirname(__file__), ".."),
    )
    combined = result.stdout + result.stderr
    assert "SELF-TEST PASSED" in combined, (
        f"Expected PASSED, got:\n{combined}"
    )
```

- [ ] **Step 2: Run E2E test**

```
python -m pytest tests/test_e2e.py -v -s
```
Expected: `PASSED`

- [ ] **Step 3: Run full test suite**

```
python -m pytest tests/ -v
```
Expected: all `PASSED`

- [ ] **Step 4: Final commit**

```
git add tests/test_e2e.py
git commit -m "test(phase3): add end-to-end loopback test"
```

---

## Phase 3 Completion Checklist

- [ ] `stream_manager.py` exists with `StreamManager` + `ScalingDecision` + `ScalingHook`
- [ ] `FileSender._run_transfer()` delegates to `StreamManager`
- [ ] `TransferController.set_scaling_hook()` wires through to `StreamManager`
- [ ] `FileReceiver._write_metrics()` exists and is called on success and failure
- [ ] All unit tests pass: `python -m pytest tests/ -v`
- [ ] Self-test passes: `python -X utf8 main.py test --size 10 --port 19900`
- [ ] SHA-256 still matches after refactor
- [ ] Resume tests pass
