"""
pacing.py — StepClimbPacingController

Phase 4 pacing: multi-phase step-climb with loss-driven phase transitions.

State machine
─────────────
COARSE  Start at initial_rate (50 MB/s).  Every coarse_interval_s (2.5s)
        with no loss: +coarse_step_mbs (10 MB/s).
        12 consecutive chunk losses → drop to last_good_mbs, enter FINE.

FINE    Every fine_interval_s (2.5s) with no loss: +fine_step_mbs (1 MB/s).
        12 consecutive chunk losses → drop to last_good_mbs, enter MICRO.

MICRO   Every micro_interval_s (1.0s) with no loss: +micro_step_mbs (0.1 MB/s).
        12 consecutive chunk losses → drop one micro step, enter HOLD.

HOLD    Equilibrium.  Every hold_interval_s (2.5s) probe +micro_step_mbs.
        12 consecutive chunk losses → drop one micro step, stay HOLD.
        Clean probe → last_good updated, stay HOLD (keep probing).

"12 consecutive chunk losses" means 12 consecutive WSAENOBUFS without a
successful send in between.  A single successful send resets the counter.

Loss direction   — exclusively loss events (record_loss)
Upward direction — exclusively clean timer intervals (record_success)
THROUGHPUT_REPORT — updates stable_mbps for logging/display only;
                    does NOT drive target_mbps in this model.
"""

import collections
import logging
import math
import threading
import time
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# ── Phase constants ────────────────────────────────────────────────────────────

_PHASE_COARSE = "COARSE"
_PHASE_FINE   = "FINE"
_PHASE_MICRO  = "MICRO"
_PHASE_HOLD   = "HOLD"

# ── Defaults ──────────────────────────────────────────────────────────────────

_DEFAULT_INITIAL_MBS       = 50.0
_DEFAULT_MIN_MBS           = 10.0
_DEFAULT_LOSS_THRESHOLD    = 12        # consecutive WSAENOBUFS to trigger phase change

_DEFAULT_COARSE_STEP_MBS   = 10.0
_DEFAULT_FINE_STEP_MBS     = 1.0
_DEFAULT_MICRO_STEP_MBS    = 0.1      # 100 KB/s

_DEFAULT_COARSE_INTERVAL_S = 2.5
_DEFAULT_FINE_INTERVAL_S   = 2.5
_DEFAULT_MICRO_INTERVAL_S  = 1.0
_DEFAULT_HOLD_INTERVAL_S   = 2.5

_DEFAULT_RESEND_RATE_FACTOR = 0.80
_MAX_SANE_MBS               = 10_000.0
_MAX_METRICS_RECORDS        = 10_000

# Kept for backward-compat import by external code
LOSS_THRESHOLD: int = _DEFAULT_LOSS_THRESHOLD


class ThroughputBasedPacingController:
    """
    Step-climb pacing controller.

    Constructor accepts all legacy kwargs so sender.py does not need
    changes.  The step-climb params below are the ones that matter;
    all others are accepted but ignored.
    """

    def __init__(
        self,
        num_streams: int,
        chunk_size: int,
        # ── Step-climb params (new) ────────────────────────────────────────
        loss_threshold: int      = _DEFAULT_LOSS_THRESHOLD,
        initial_rate_mbs: float  = _DEFAULT_INITIAL_MBS,
        min_rate_mbs: float      = _DEFAULT_MIN_MBS,
        coarse_step_mbs: float   = _DEFAULT_COARSE_STEP_MBS,
        fine_step_mbs: float     = _DEFAULT_FINE_STEP_MBS,
        micro_step_mbs: float    = _DEFAULT_MICRO_STEP_MBS,
        coarse_interval_s: float = _DEFAULT_COARSE_INTERVAL_S,
        fine_interval_s: float   = _DEFAULT_FINE_INTERVAL_S,
        micro_interval_s: float  = _DEFAULT_MICRO_INTERVAL_S,
        hold_interval_s: float   = _DEFAULT_HOLD_INTERVAL_S,
        # ── Per-tier loss callback (optional) ─────────────────────────────
        # Signature: (post_transition_mbps: float) -> float
        # Called after each loss-triggered phase transition with the rate
        # already adjusted by the step-climb state machine.  The return
        # value replaces target_mbps (clamped to min_rate_mbs).
        # Tiers 1–3 inject a closure that applies an additional step-down;
        # Tier 0 passes None so existing behaviour is completely unchanged.
        loss_event_callback: Optional[Callable[[float], float]] = None,
        # ── Legacy / ignored kwargs (kept for compat) ──────────────────────
        max_growth_percent: float            = 10.0,
        max_reduction_percent: float         = 20.0,
        measurement_window_ms: int           = 5000,
        min_adjustment_interval_ms: int      = 250,
        tier_change_min_interval_ms: int     = 250,
        recovery_interval_ms: int            = 1500,
        starting_tier: str                   = "5GbE",
        stable_window_chunks: int            = 12,
        target_overhead_pct: float           = 2.5,
        convergence_loss_pct: float          = 0.1,
        window_loss_threshold_pct: float     = 5.0,
        **kwargs,
    ) -> None:

        self._num_streams = num_streams
        self._chunk_size  = chunk_size
        self._loss_event_callback: Optional[Callable[[float], float]] = loss_event_callback

        self._min_mbs          = max(1.0, float(min_rate_mbs))
        self._loss_threshold   = max(1, int(loss_threshold))

        self._coarse_step_mbs  = max(0.1, float(coarse_step_mbs))
        self._fine_step_mbs    = max(0.01, float(fine_step_mbs))
        self._micro_step_mbs   = max(0.001, float(micro_step_mbs))

        self._coarse_interval_s = max(0.1, float(coarse_interval_s))
        self._fine_interval_s   = max(0.1, float(fine_interval_s))
        self._micro_interval_s  = max(0.1, float(micro_interval_s))
        self._hold_interval_s   = max(0.1, float(hold_interval_s))

        initial = max(self._min_mbs, float(initial_rate_mbs))

        self._target_mbs:       float = initial
        self._stable_mbs:       float = initial   # high-water mark from THROUGHPUT_REPORT
        self._last_good_mbs:    float = initial   # last target before a loss-triggered drop
        self._rate_hint_cap:    float = 0.0       # from receiver RATE_HINT (0 = unlimited)

        self._phase:            str   = _PHASE_COARSE
        self._consecutive_loss: int   = 0

        now = time.monotonic()
        self._last_step_time:   float = now       # when we last stepped up
        self._phase_start_time: float = now

        # Resend mode: temporarily cap target during resend passes
        self._in_resend_mode: bool  = False
        self._resend_cap_mbs: float = initial

        # Metrics ring buffer
        self._metrics_log: collections.deque = collections.deque(maxlen=_MAX_METRICS_RECORDS)
        self._lock = threading.Lock()

        logger.info(
            "StepClimbPacing INIT  "
            "start=%.1f MB/s  min=%.1f MB/s  loss_threshold=%d  "
            "COARSE +%.0f MB/s/%.1fs  FINE +%.1f MB/s/%.1fs  "
            "MICRO +%.3f MB/s/%.1fs  HOLD probe/%.1fs  "
            "streams=%d  chunk=%d B",
            initial, self._min_mbs, self._loss_threshold,
            self._coarse_step_mbs, self._coarse_interval_s,
            self._fine_step_mbs,   self._fine_interval_s,
            self._micro_step_mbs,  self._micro_interval_s,
            self._hold_interval_s,
            num_streams, chunk_size,
        )

    # ── Public properties ──────────────────────────────────────────────────────

    @property
    def delay_s(self) -> float:
        with self._lock:
            return self._compute_delay_locked(self._target_mbs)

    @property
    def tier_name(self) -> str:
        with self._lock:
            mbs   = self._target_mbs
            phase = self._phase
        if mbs >= 1_024:
            return f"{mbs / 1_024:.2f} GB/s [{phase}]"
        return f"{mbs:.2f} MB/s [{phase}]"

    @property
    def target_mbps(self) -> float:
        with self._lock:
            return self._target_mbs

    @property
    def stable_rate_mbps(self) -> float:
        with self._lock:
            return self._stable_mbs

    @property
    def measured_mbps(self) -> float:
        # Kept for compat — stable is the closest equivalent in this model
        with self._lock:
            return self._stable_mbs

    @property
    def loss_threshold(self) -> int:
        return self._loss_threshold

    @property
    def consecutive_clean(self) -> int:
        # Kept for compat — not meaningful in step-climb model
        return 0

    def get_metrics_snapshot(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._metrics_log)

    # ── Core pacing interface ──────────────────────────────────────────────────

    def record_success(self, stream_id: int) -> None:
        """
        Called after every successful chunk send.

        Resets the consecutive loss counter, then checks whether the step
        timer has elapsed.  If so, steps up according to the current phase.
        Only one step fires per interval regardless of how many streams call
        simultaneously (lock ensures atomicity of the check-and-update).
        """
        now = time.monotonic()
        with self._lock:
            self._consecutive_loss = 0
            interval = self._get_interval_locked()
            if now - self._last_step_time < interval:
                return
            self._last_step_time = now
            self._step_up_locked(stream_id, now)

    def record_loss(self, stream_id: int) -> None:
        """
        Called on every WSAENOBUFS.

        Increments the consecutive loss counter.  When the counter reaches
        loss_threshold, triggers a phase transition (or in HOLD, a micro
        step-down) and resets the counter.
        """
        with self._lock:
            self._consecutive_loss += 1
            if self._consecutive_loss < self._loss_threshold:
                return
            self._consecutive_loss = 0
            self._on_loss_locked(stream_id)

    def step_down(self, stream_id: int) -> float:
        """
        No-op in step-climb model.  Loss handling is done entirely in
        record_loss().  Kept so sender.py does not require changes.
        """
        with self._lock:
            return self._compute_delay_locked(self._target_mbs)

    # ── THROUGHPUT_REPORT (informational only in this model) ──────────────────

    def update_stable(self, mbps: float) -> None:
        """
        Updates stable_mbps (high-water mark) for display and metrics.
        Does NOT drive target_mbps — target is exclusively controlled by
        the step-climb state machine.
        """
        if not math.isfinite(mbps) or mbps <= 0:
            return
        with self._lock:
            reported = min(max(float(mbps), self._min_mbs), _MAX_SANE_MBS)
            if reported > self._stable_mbs:
                old = self._stable_mbs
                self._stable_mbs = reported
                logger.debug(
                    "STABLE ↑  %.1f → %.1f MB/s  (display only, target=%.1f)",
                    old, reported, self._target_mbs,
                )

    def set_rate_hint_cap(self, max_mbps: float) -> None:
        """
        Sets an upper ceiling on target_mbps from receiver RATE_HINT.
        0.0 = no cap.
        """
        with self._lock:
            cap = max(0.0, float(max_mbps))
            self._rate_hint_cap = cap
            if cap > 0 and self._target_mbs > cap:
                old = self._target_mbs
                self._target_mbs    = cap
                self._last_good_mbs = min(self._last_good_mbs, cap)
                logger.info(
                    "RATE_HINT cap: target %.1f → %.1f MB/s",
                    old, self._target_mbs,
                )
            logger.info(
                "Rate hint cap set: %.1f MB/s (%s)",
                cap, "unlimited" if cap == 0 else "active",
            )

    def set_resend_mode(self, enabled: bool, base_rate_mbs: float = None) -> None:
        """
        Enable/disable resend mode.

        base_rate_mbs: anchor for the 80% cap.  Pass the rate captured at
        FINISH time on every resend pass.  Without this, the cap compounds:
        151 → 121 → 95 → 76 → 61 → ...  With it, every pass caps at the
        same fixed ceiling (e.g. 151 × 80% = 121 MB/s) regardless of how
        many passes have run.
        """
        with self._lock:
            if enabled == self._in_resend_mode:
                return
            self._in_resend_mode = enabled
            if enabled:
                anchor = base_rate_mbs if base_rate_mbs is not None else self._target_mbs
                cap    = max(self._min_mbs, anchor * _DEFAULT_RESEND_RATE_FACTOR)
                self._resend_cap_mbs = cap
                old = self._target_mbs
                if self._target_mbs > cap:
                    self._target_mbs = cap
                logger.info(
                    "RESEND mode ON   %.1f → %.1f MB/s  "
                    "(anchor=%.1f × %.0f%%)",
                    old, self._target_mbs,
                    anchor, _DEFAULT_RESEND_RATE_FACTOR * 100,
                )
            else:
                logger.info(
                    "RESEND mode OFF  resuming %.1f MB/s  phase=%s",
                    self._target_mbs, self._phase,
                )

    # ── Internals ──────────────────────────────────────────────────────────────

    def _get_interval_locked(self) -> float:
        if self._phase == _PHASE_COARSE:
            return self._coarse_interval_s
        if self._phase == _PHASE_FINE:
            return self._fine_interval_s
        if self._phase == _PHASE_MICRO:
            return self._micro_interval_s
        return self._hold_interval_s   # HOLD

    def _effective_cap_locked(self) -> float:
        """Return the active upper ceiling (rate hint or unlimited)."""
        cap = self._rate_hint_cap
        if self._in_resend_mode:
            cap = min(cap, self._resend_cap_mbs) if cap > 0 else self._resend_cap_mbs
        return cap if cap > 0 else _MAX_SANE_MBS

    def _step_up_locked(self, stream_id: int, now: float) -> None:
        """Apply one upward step for the current phase."""
        cap     = self._effective_cap_locked()
        old     = self._target_mbs
        phase   = self._phase

        if phase == _PHASE_COARSE:
            self._last_good_mbs = old
            new = min(old + self._coarse_step_mbs, cap)
        elif phase == _PHASE_FINE:
            self._last_good_mbs = old
            new = min(old + self._fine_step_mbs, cap)
        elif phase == _PHASE_MICRO:
            self._last_good_mbs = old
            new = min(old + self._micro_step_mbs, cap)
        else:  # HOLD — probe one micro step
            self._last_good_mbs = old
            new = min(old + self._micro_step_mbs, cap)

        self._target_mbs = max(self._min_mbs, new)

        if abs(self._target_mbs - old) > 0.001:
            logger.info(
                "STEP UP [%s]  %.3f → %.3f MB/s  "
                "(last_good=%.3f  cap=%.1f  stream=%d)",
                phase, old, self._target_mbs, self._last_good_mbs, cap, stream_id,
            )
            self._metrics_log.append({
                "t":          round(now, 3),
                "event":      "step_up",
                "phase":      phase,
                "target_mbs": round(self._target_mbs, 3),
                "old_mbs":    round(old, 3),
                "last_good":  round(self._last_good_mbs, 3),
            })

    def _on_loss_locked(self, stream_id: int) -> None:
        """Handle loss_threshold consecutive losses — phase transition or step-down."""
        now   = time.monotonic()
        old   = self._target_mbs
        phase = self._phase

        if phase == _PHASE_COARSE:
            # Drop to last confirmed good rate, enter fine-grained search
            new        = max(self._min_mbs, self._last_good_mbs)
            self._target_mbs    = new
            self._last_good_mbs = new
            self._phase         = _PHASE_FINE
            self._phase_start_time = now
            self._last_step_time   = now
            logger.warning(
                "LOSS [COARSE → FINE]  "
                "%d consec losses  %.1f → %.1f MB/s  "
                "(dropped to last_good, now +%.1f MB/s / %.1fs)",
                self._loss_threshold, old, new,
                self._fine_step_mbs, self._fine_interval_s,
            )

        elif phase == _PHASE_FINE:
            # Drop to last confirmed good rate, enter micro-step search
            new        = max(self._min_mbs, self._last_good_mbs)
            self._target_mbs    = new
            self._last_good_mbs = new
            self._phase         = _PHASE_MICRO
            self._phase_start_time = now
            self._last_step_time   = now
            logger.warning(
                "LOSS [FINE → MICRO]  "
                "%d consec losses  %.1f → %.3f MB/s  "
                "(dropped to last_good, now +%.3f MB/s / %.1fs)",
                self._loss_threshold, old, new,
                self._micro_step_mbs, self._micro_interval_s,
            )

        else:
            # MICRO or HOLD — drop one micro step, enter/stay HOLD
            new        = max(self._min_mbs, old - self._micro_step_mbs)
            self._target_mbs    = new
            self._last_good_mbs = new
            prev_phase = self._phase
            self._phase         = _PHASE_HOLD
            self._phase_start_time = now
            self._last_step_time   = now
            logger.warning(
                "LOSS [%s → HOLD]  "
                "%d consec losses  %.3f → %.3f MB/s  "
                "(−%.3f MB/s  probe every %.1fs)",
                prev_phase, self._loss_threshold, old, new,
                self._micro_step_mbs, self._hold_interval_s,
            )

        self._metrics_log.append({
            "t":            round(now, 3),
            "event":        "loss_transition",
            "from_phase":   phase,
            "to_phase":     self._phase,
            "old_mbs":      round(old, 3),
            "new_mbs":      round(self._target_mbs, 3),
            "consec_loss":  self._loss_threshold,
            "stream_id":    stream_id,
        })

        # Per-tier extra step-down (Tiers 1–3 only; Tier 0 callback is None).
        # Applied after the standard phase transition so the floor is always
        # at least min_mbs, and the metrics log already captures the
        # state-machine transition above.
        if self._loss_event_callback is not None:
            adjusted = self._loss_event_callback(self._target_mbs)
            self._target_mbs = max(self._min_mbs, float(adjusted))

    def _compute_delay_locked(self, mbs: float) -> float:
        if not math.isfinite(mbs) or mbs <= 0:
            mbs = self._min_mbs
        mbs = min(mbs, _MAX_SANE_MBS)
        # total bytes per second across all streams = mbs × 1_048_576
        # time per chunk (one chunk sent per cycle across all streams)
        return (self._num_streams * self._chunk_size) / (mbs * 1_048_576)


# ── Backward-compat alias ─────────────────────────────────────────────────────

AdaptivePacingController = ThroughputBasedPacingController
