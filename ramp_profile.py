"""
ramp_profile.py — RampProfile dataclass.

Kept as a standalone module so pacing.py (or future components) can import
it without pulling in the full peer_db dependency chain.
"""

from dataclasses import dataclass


@dataclass
class RampProfile:
    """
    Parameters that govern how the pacing engine starts and ramps up for a
    particular peer session.

    start_mbps      — initial_rate_mbs passed to AdaptivePacingController.
                      For known peers this is the recorded stable speed;
                      for unknown peers it is the configured cold-start default.
    step_mbps       — passed as coarse_step_mbs to AdaptivePacingController,
                      overriding the global pacing.coarse_step_mbps config.
    interval_sec    — stored for DB record-keeping; same caveat as step_mbps.
    step_down_mbps  — how many MB/s to subtract from the post-transition rate
                      each time loss_threshold consecutive losses fire.
                      Used by the loss_event_callback closure; 0.0 disables
                      the extra step-down (Tier 0 behaviour).
    loss_threshold  — consecutive WSAENOBUFS count passed to pacing engine.
                      Higher tiers use a larger threshold so near-ceiling
                      sessions are less sensitive to transient noise.
    """
    start_mbps:     float
    step_mbps:      float
    interval_sec:   float
    step_down_mbps: float
    loss_threshold: int
