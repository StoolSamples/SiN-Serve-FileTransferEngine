"""
window.py — WindowController + RTTEstimator for Phase 4 sliding window.

WindowController implements a fixed-size semaphore gate:
  - acquire() before sending a chunk (blocks workers when in-flight == max)
  - release() ONLY when a chunk is ACKed via SACK (in sender feedback listener)
  - _in_flight tracks the actual number of outstanding unacknowledged chunks

RTTEstimator implements EWMA smoothing (RFC 6298 simplified):
  - srtt = smoothed round-trip time
  - rttvar = RTT variance (stored, not yet used for RTO calculation)

RTT-adaptive window expansion is a placeholder: set_rtt_adaptive(True) stores
the flag but performs no resize.  When enabled in a future phase, update_rtt()
will recompute _max_window as ceil(srtt * send_rate_chunks_per_s).
"""

import logging
import threading
from typing import Optional

logger = logging.getLogger(__name__)


# ── RTT Estimator ─────────────────────────────────────────────────────────────

class RTTEstimator:
    """
    EWMA-based round-trip time estimator.

    update(sample_s) feeds a new RTT measurement.
    srtt is None until the first sample arrives.
    """

    def __init__(self, alpha: float = 0.125) -> None:
        self._alpha  = max(0.001, min(1.0, float(alpha)))
        self._srtt:  Optional[float] = None
        self._rttvar: float = 0.0
        self._lock   = threading.Lock()

    def update(self, sample_s: float) -> None:
        """Feed one RTT sample (seconds).  Negative or zero values are ignored."""
        if sample_s <= 0:
            return
        with self._lock:
            if self._srtt is None:
                # First sample: initialise directly (RFC 6298 §2.2)
                self._srtt  = sample_s
                self._rttvar = sample_s / 2.0
            else:
                delta        = abs(self._srtt - sample_s)
                self._rttvar = 0.75 * self._rttvar + 0.25 * delta
                self._srtt   = (1.0 - self._alpha) * self._srtt + self._alpha * sample_s

    @property
    def srtt(self) -> Optional[float]:
        """Smoothed RTT in seconds, or None if no samples yet."""
        with self._lock:
            return self._srtt

    @property
    def rttvar(self) -> float:
        """RTT variance in seconds (stored for future RTO calculation)."""
        with self._lock:
            return self._rttvar


# ── Window Controller ─────────────────────────────────────────────────────────

class WindowController:
    """
    Fixed-size sliding window gate backed by a threading.BoundedSemaphore.

    Lifecycle (per chunk):
        1.  window.acquire()           — worker acquires slot before sending
        2.  chunk sent over UDP        — chunk is now in-flight
        3.  SACK arrives at sender     — feedback listener calls window.release(n)
        4.  slot returned to semaphore — next waiting worker may proceed

    _in_flight is the authoritative count of outstanding unacknowledged chunks.
    release() uses min(count, _in_flight) to prevent over-release without
    relying on exceptions.
    """

    def __init__(self, window_size: int, rtt_estimator: RTTEstimator) -> None:
        if window_size < 1:
            raise ValueError(f"window_size must be >= 1, got {window_size}")
        self._max_window    = window_size
        self._rtt_estimator = rtt_estimator
        self._rtt_adaptive  = False

        self._sem        = threading.BoundedSemaphore(window_size)
        self._in_flight  = 0
        self._lock       = threading.Lock()

        logger.info(
            "WindowController init  max=%d  rtt_adaptive=%s",
            window_size, self._rtt_adaptive,
        )

    # ── Slot management ───────────────────────────────────────────────────────

    def acquire(self, timeout: float = 1.0) -> bool:
        """
        Acquire one window slot (blocks until available or timeout).

        Returns True on success (slot acquired, _in_flight incremented).
        Returns False on timeout (slot NOT acquired, _in_flight unchanged).
        """
        acquired = self._sem.acquire(timeout=timeout)
        if acquired:
            with self._lock:
                self._in_flight += 1
        return acquired

    def release(self, count: int = 1) -> None:
        """
        Release up to `count` window slots.

        actual_release = min(count, _in_flight) prevents over-release without
        relying on BoundedSemaphore ValueError exceptions.

        Must ONLY be called from the ACK/SACK handling path — never from the
        send path or finally blocks.
        """
        if count <= 0:
            return
        with self._lock:
            actual_release  = min(count, self._in_flight)
            self._in_flight -= actual_release

        for _ in range(actual_release):
            self._sem.release()

        if actual_release < count:
            logger.debug(
                "WindowController.release: clamped %d → %d  "
                "(over-release guard, in_flight was %d)",
                count, actual_release, actual_release,
            )

    # ── RTT integration ───────────────────────────────────────────────────────

    def update_rtt(self, sample_s: float) -> None:
        """
        Forward an RTT sample to the estimator.

        When _rtt_adaptive is True (future phase), this will also recompute
        _max_window as ceil(srtt * send_rate_chunks_per_s).  Currently a no-op
        beyond forwarding the sample.
        """
        self._rtt_estimator.update(sample_s)
        if self._rtt_adaptive:
            # Placeholder: adaptive resize logic goes here
            pass

    def set_rtt_adaptive(self, enabled: bool) -> None:
        """
        Enable or disable RTT-adaptive window sizing (placeholder).

        Setting True stores the flag; no resize logic is active yet.
        """
        self._rtt_adaptive = bool(enabled)
        logger.info(
            "WindowController: rtt_adaptive=%s  "
            "(placeholder — no adaptive resize implemented)",
            self._rtt_adaptive,
        )

    # ── Observability ─────────────────────────────────────────────────────────

    @property
    def in_flight(self) -> int:
        """Current number of outstanding unacknowledged chunks."""
        with self._lock:
            return self._in_flight

    @property
    def max_window(self) -> int:
        """Configured maximum window size (slots)."""
        return self._max_window
