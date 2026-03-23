
import json
import os
import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)

DEFAULT_CONFIG: Dict[str, Any] = {
    "transfer": {
        "chunk_size": 61440,
        "base_port": 9000,
        # Phase 4 port layout derived from base_port:
        #   base_port+0 (9000) = control
        #   base_port+1 (9001) = feedback (sender binds and listens)
        #   base_port+2..+5   = data streams
        "num_streams": 4,
        "socket_buffer_mb": 64,
        "ack_timeout": 5.0,
        "max_retries": 20,
        "window_size": 256,
        "resend_check_interval": 3.0,
        "recv_timeout": 600.0,
        "inter_packet_delay": 0.0,
        "send_delay_us": 500,
    },
    "pacing": {
        # Step-climb phase parameters
        # See pacing.py for full state-machine description.

        # Starting rate.  Set to a realistic lower bound for your link.
        # The COARSE phase will climb quickly from here.
        "initial_rate_mbps": 50,

        # Number of consecutive WSAENOBUFS (chunk send failures) that
        # trigger a phase transition or step-down.  A single successful
        # send resets the counter.
        "loss_threshold": 12,

        # COARSE phase: +coarse_step_mbps every coarse_interval_s
        "coarse_step_mbps":   10.0,
        "coarse_interval_s":  2.5,

        # FINE phase: +fine_step_mbps every fine_interval_s
        "fine_step_mbps":     1.0,
        "fine_interval_s":    2.5,

        # MICRO phase: +micro_step_mbps every micro_interval_s
        # 0.1 MB/s = 100 KB/s
        "micro_step_mbps":    0.1,
        "micro_interval_s":   1.0,

        # HOLD phase: probe +micro_step_mbps every hold_interval_s
        # Loss in HOLD: drop one micro step, stay HOLD
        "hold_interval_s":    2.5,

        "min_rate_mbps":      10,

        # rate_hint_mbps: sender upper speed cap.
        # 0 = no configured limit; receiver RATE_HINT may still apply a cap.
        "rate_hint_mbps":     0.0,

        # throughput_report_interval_ms: how often receiver sends delivery
        # rate report. Used for display / metrics only in this pacing model.
        "throughput_report_interval_ms": 500,
    },
    "crypto": {
        "enabled": False,
        "algorithm": "AES-256-GCM",
    },
    "rate_limiter": {
        "enabled": False,
        "send_limit_mbps": 0,
        "recv_limit_mbps": 0,
    },
    "logging": {
        "level": "INFO",
        "log_to_file": False,
        "log_file": "fasttransfer.log",
    },
    "phase3": {
        "resume_enabled": False,
        "progress_interval_ms": 250,
        "sidecar_flush_interval": 64,
        "sack_enabled": False,
        "session_blackout_s": 10.0,
        "metrics_enabled": False,
        "metrics_file": ".ft_metrics.json",
    },
    "ram": {
        # allow_ram_loading: if True and the file fits in available RAM
        # (after reserving ram_amount_reserved_gb), the receiver will
        # buffer the entire file in memory and write once at the end.
        # This eliminates the write queue, removes the FINISH audit
        # overcount, and dramatically reduces vCPU pressure.
        "allow_ram_loading": True,
        # ram_amount_reserved_gb: RAM to leave free for the OS and other
        # processes.  Supports two decimal places (e.g. 8.50).
        "ram_amount_reserved_gb": 8.00,
    },
    "peer_db": {
        # Path to the SQLite peer database (relative to working directory).
        "db_path": "peer_db.sqlite",

        # ── Tier 0: first-time peers (send_count == 0) ────────────────────────
        # Cold-start from unknown_ramp_start_mbps; no loss callback.
        "unknown_ramp_start_mbps":      50.0,
        "tier0_ramp_step_mbps":          1.0,
        "tier0_ramp_interval_sec":       5.0,
        "tier0_ramp_step_down_mbps":     0.0,   # no extra step-down for Tier 0
        "tier0_loss_threshold":         12,

        # ── Tier 1: send_count 1–9 ────────────────────────────────────────────
        # Start at avg_stable_mbps; gentle step-down on loss.
        "tier1_ramp_step_mbps":          0.5,
        "tier1_ramp_interval_sec":       7.5,
        "tier1_ramp_step_down_mbps":     0.5,
        "tier1_loss_threshold":         16,

        # ── Tier 2: send_count 10–19 ──────────────────────────────────────────
        # More conservative; smaller step-down.
        "tier2_ramp_step_mbps":          0.1,
        "tier2_ramp_interval_sec":      10.0,
        "tier2_ramp_step_down_mbps":     0.3,
        "tier2_loss_threshold":         20,

        # ── Tier 3: send_count ≥ 20 ───────────────────────────────────────────
        # Well-characterised link; very fine probing.
        "tier3_ramp_step_mbps":          0.05,
        "tier3_ramp_interval_sec":      10.0,
        "tier3_ramp_step_down_mbps":     0.1,
        "tier3_loss_threshold":         24,

        # ── Floor ratio for loss callbacks (Tiers 1-3) ────────────────────────
        # The callback will never drop below: start_mbps * loss_floor_ratio.
        "loss_floor_ratio":              0.5,

        # ── Absolute ceiling applied to all ramp profiles ──────────────────────
        "ramp_ceiling_mbps":          4500.0,
    },
    "integrity": {
        # Per-chunk verification (xxHash XXH3-64) is ALWAYS ON.
        # Cannot be disabled from either side.

        # ── Sender-side controls (sender's config.json) ───────────────────────

        # hash_disabled: true  → sender will NEVER compute a whole-file SHA-256,
        #   regardless of what the receiver requests.  Zero hash sent in FINISH.
        #   Use this when SHA computation overhead is unacceptable.
        # hash_disabled: false → sender respects receiver's request and its own
        #   hash_required setting.  Default: false.
        "hash_disabled": False,

        # hash_required: true  → sender ALWAYS computes SHA-256 and the receiver
        #   MUST verify it.  Overrides receiver's hash_requested preference.
        #   Receiver cannot opt out when this is true.
        # hash_required: false → sender only computes SHA-256 if the receiver
        #   requests it (and hash_disabled is false).  Default: false.
        "hash_required": False,

        # ── Receiver-side control (receiver's config.json) ────────────────────

        # hash_requested: true  → receiver asks the sender to compute SHA-256.
        #   The sender will honour this unless hash_disabled is true on their end.
        #   This is a REQUEST, not a demand — the sender has final say.
        # hash_requested: false → receiver does not ask for SHA-256.  Default: false.
        "hash_requested": False,
    },
}


class Config:

    def __init__(self, config_path: str = "config.json") -> None:
        self._data: Dict[str, Any] = self._deep_copy(DEFAULT_CONFIG)
        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as fh:
                    loaded = json.load(fh)
                self._deep_merge(self._data, loaded)
                logger.info("Loaded config from %s", config_path)
            except (json.JSONDecodeError, IOError) as exc:
                logger.warning("Failed to load %s: %s — using defaults.", config_path, exc)
        else:
            logger.info("Config file %s not found; using defaults.", config_path)

    @staticmethod
    def _deep_copy(src: dict) -> dict:
        import copy
        return copy.deepcopy(src)

    def _deep_merge(self, base: dict, override: dict) -> None:
        for key, val in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(val, dict):
                self._deep_merge(base[key], val)
            else:
                base[key] = val

    def get(self, *keys: str, default: Any = None) -> Any:
        node = self._data
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return node

    def save(self, path: str = "config.json") -> None:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self._data, fh, indent=2)

    # ── transfer ──────────────────────────────────────────────────────────────

    @property
    def chunk_size(self) -> int:
        return int(self.get("transfer", "chunk_size", default=61440))

    @property
    def base_port(self) -> int:
        return int(self.get("transfer", "base_port", default=9000))

    @property
    def feedback_port(self) -> int:
        """Sender binds and listens here.  Receiver sends feedback to sender:feedback_port."""
        return self.base_port + 1

    @property
    def data_base_port(self) -> int:
        """First data stream port.  Streams occupy data_base_port .. data_base_port+num_streams-1."""
        return self.base_port + 2

    @property
    def num_streams(self) -> int:
        raw = int(self.get("transfer", "num_streams", default=4))
        return max(1, min(raw, 16))

    @property
    def socket_buffer_mb(self) -> int:
        raw = int(self.get("transfer", "socket_buffer_mb", default=64))
        return max(1, min(raw, 512))

    @property
    def socket_buffer_size(self) -> int:
        return self.socket_buffer_mb * 1_048_576

    @property
    def send_delay_us(self) -> int:
        return max(0, int(self.get("transfer", "send_delay_us", default=50)))

    @property
    def ack_timeout(self) -> float:
        return float(self.get("transfer", "ack_timeout", default=5.0))

    @property
    def max_retries(self) -> int:
        return int(self.get("transfer", "max_retries", default=20))

    @property
    def window_size(self) -> int:
        return int(self.get("transfer", "window_size", default=256))

    @property
    def resend_check_interval(self) -> float:
        return float(self.get("transfer", "resend_check_interval", default=3.0))

    @property
    def recv_timeout(self) -> float:
        return float(self.get("transfer", "recv_timeout", default=600.0))

    @property
    def inter_packet_delay(self) -> float:
        return float(self.get("transfer", "inter_packet_delay", default=0.0))

    # ── pacing ────────────────────────────────────────────────────────────────

    @property
    def initial_rate_mbps(self) -> float:
        return max(1.0, float(self.get("pacing", "initial_rate_mbps", default=50.0)))

    @property
    def loss_threshold(self) -> int:
        return max(1, int(self.get("pacing", "loss_threshold", default=12)))

    @property
    def coarse_step_mbps(self) -> float:
        return max(0.1, float(self.get("pacing", "coarse_step_mbps", default=10.0)))

    @property
    def coarse_interval_s(self) -> float:
        return max(0.1, float(self.get("pacing", "coarse_interval_s", default=2.5)))

    @property
    def fine_step_mbps(self) -> float:
        return max(0.01, float(self.get("pacing", "fine_step_mbps", default=1.0)))

    @property
    def fine_interval_s(self) -> float:
        return max(0.1, float(self.get("pacing", "fine_interval_s", default=2.5)))

    @property
    def micro_step_mbps(self) -> float:
        return max(0.001, float(self.get("pacing", "micro_step_mbps", default=0.1)))

    @property
    def micro_interval_s(self) -> float:
        return max(0.1, float(self.get("pacing", "micro_interval_s", default=1.0)))

    @property
    def hold_interval_s(self) -> float:
        return max(0.1, float(self.get("pacing", "hold_interval_s", default=2.5)))

    @property
    def min_rate_mbps(self) -> float:
        return max(1.0, float(self.get("pacing", "min_rate_mbps", default=10.0)))

    @property
    def rate_hint_mbps(self) -> float:
        return max(0.0, float(self.get("pacing", "rate_hint_mbps", default=0.0)))

    @property
    def throughput_report_interval_ms(self) -> int:
        return max(100, int(self.get("pacing", "throughput_report_interval_ms", default=500)))

    # ── pacing compat shims (properties removed in step-climb rewrite) ────────
    # transfer_controller.py and any other callers that reference the old
    # THROUGHPUT_REPORT-era properties will not crash.  All return reasonable
    # defaults; none of these values drive pacing behaviour any more.

    @property
    def tier_change_min_interval_ms(self) -> int:
        return 250

    @property
    def recovery_interval_ms(self) -> int:
        return 1500

    @property
    def starting_tier(self) -> str:
        return "step-climb"

    @property
    def max_growth_percent(self) -> float:
        return 10.0

    @property
    def max_reduction_percent(self) -> float:
        return 20.0

    @property
    def measurement_window_ms(self) -> int:
        return 5000

    @property
    def stable_window_chunks(self) -> int:
        return 12

    @property
    def target_overhead_pct(self) -> float:
        return 2.5

    @property
    def convergence_loss_pct(self) -> float:
        return 0.1

    @property
    def window_loss_threshold_pct(self) -> float:
        return 5.0

    # ── crypto ────────────────────────────────────────────────────────────────

    @property
    def crypto_enabled(self) -> bool:
        return bool(self.get("crypto", "enabled", default=False))

    # ── rate limiter ──────────────────────────────────────────────────────────

    @property
    def rate_limiter_enabled(self) -> bool:
        return bool(self.get("rate_limiter", "enabled", default=False))

    @property
    def send_limit_mbps(self) -> float:
        return float(self.get("rate_limiter", "send_limit_mbps", default=0))

    @property
    def recv_limit_mbps(self) -> float:
        return float(self.get("rate_limiter", "recv_limit_mbps", default=0))

    # ── logging ───────────────────────────────────────────────────────────────

    @property
    def log_level(self) -> str:
        return str(self.get("logging", "level", default="INFO")).upper()

    @property
    def log_to_file(self) -> bool:
        return bool(self.get("logging", "log_to_file", default=False))

    @property
    def log_file(self) -> str:
        return str(self.get("logging", "log_file", default="fasttransfer.log"))

    # ── Phase 3 ───────────────────────────────────────────────────────────────

    @property
    def resume_enabled(self) -> bool:
        return bool(self.get("phase3", "resume_enabled", default=False))

    @property
    def progress_interval_ms(self) -> int:
        return max(50, int(self.get("phase3", "progress_interval_ms", default=250)))

    @property
    def sidecar_flush_interval(self) -> int:
        return max(1, int(self.get("phase3", "sidecar_flush_interval", default=64)))

    @property
    def sack_enabled(self) -> bool:
        return bool(self.get("phase3", "sack_enabled", default=False))

    @property
    def session_blackout_s(self) -> float:
        return max(0.0, float(self.get("phase3", "session_blackout_s", default=10.0)))

    @property
    def metrics_enabled(self) -> bool:
        return bool(self.get("phase3", "metrics_enabled", default=False))

    @property
    def metrics_file(self) -> str:
        return str(self.get("phase3", "metrics_file", default=".ft_metrics.json"))

    # ── RAM loading ───────────────────────────────────────────────────────────

    @property
    def allow_ram_loading(self) -> bool:
        return bool(self.get("ram", "allow_ram_loading", default=True))

    @property
    def ram_amount_reserved_gb(self) -> float:
        raw = float(self.get("ram", "ram_amount_reserved_gb", default=8.00))
        return round(max(0.0, raw), 2)

    # ── Integrity ─────────────────────────────────────────────────────────────

    @property
    def hash_disabled(self) -> bool:
        """Sender: never compute whole-file SHA-256. Overrides all other settings."""
        return bool(self.get("integrity", "hash_disabled", default=False))

    @property
    def hash_required(self) -> bool:
        """Sender: always compute SHA-256; receiver MUST verify. Overrides hash_requested."""
        return bool(self.get("integrity", "hash_required", default=False))

    @property
    def hash_requested(self) -> bool:
        """Receiver: ask sender to compute SHA-256. Advisory — sender may decline."""
        return bool(self.get("integrity", "hash_requested", default=False))

    # ── Backward-compat shims for old key names ───────────────────────────────

    @property
    def sender_file_hash_enabled(self) -> bool:
        """Deprecated: use hash_required / hash_disabled instead."""
        return self.hash_required and not self.hash_disabled

    @property
    def receiver_file_hash_enabled(self) -> bool:
        """Deprecated: use hash_requested instead."""
        return self.hash_requested

    # ── Peer DB ───────────────────────────────────────────────────────────────

    @property
    def peer_db_path(self) -> str:
        return str(self.get("peer_db", "db_path", default="peer_db.sqlite"))

    @property
    def unknown_ramp_start_mbps(self) -> float:
        return max(1.0, float(self.get("peer_db", "unknown_ramp_start_mbps", default=50.0)))

    # ── Tier 0 ────────────────────────────────────────────────────────────────

    @property
    def tier0_ramp_step_mbps(self) -> float:
        return max(0.01, float(self.get("peer_db", "tier0_ramp_step_mbps", default=1.0)))

    @property
    def tier0_ramp_interval_sec(self) -> float:
        return max(0.1, float(self.get("peer_db", "tier0_ramp_interval_sec", default=5.0)))

    @property
    def tier0_ramp_step_down_mbps(self) -> float:
        return max(0.0, float(self.get("peer_db", "tier0_ramp_step_down_mbps", default=0.0)))

    @property
    def tier0_loss_threshold(self) -> int:
        return max(1, int(self.get("peer_db", "tier0_loss_threshold", default=12)))

    # ── Tier 1 ────────────────────────────────────────────────────────────────

    @property
    def tier1_ramp_step_mbps(self) -> float:
        return max(0.01, float(self.get("peer_db", "tier1_ramp_step_mbps", default=0.5)))

    @property
    def tier1_ramp_interval_sec(self) -> float:
        return max(0.1, float(self.get("peer_db", "tier1_ramp_interval_sec", default=7.5)))

    @property
    def tier1_ramp_step_down_mbps(self) -> float:
        return max(0.0, float(self.get("peer_db", "tier1_ramp_step_down_mbps", default=0.5)))

    @property
    def tier1_loss_threshold(self) -> int:
        return max(1, int(self.get("peer_db", "tier1_loss_threshold", default=16)))

    # ── Tier 2 ────────────────────────────────────────────────────────────────

    @property
    def tier2_ramp_step_mbps(self) -> float:
        return max(0.01, float(self.get("peer_db", "tier2_ramp_step_mbps", default=0.1)))

    @property
    def tier2_ramp_interval_sec(self) -> float:
        return max(0.1, float(self.get("peer_db", "tier2_ramp_interval_sec", default=10.0)))

    @property
    def tier2_ramp_step_down_mbps(self) -> float:
        return max(0.0, float(self.get("peer_db", "tier2_ramp_step_down_mbps", default=0.3)))

    @property
    def tier2_loss_threshold(self) -> int:
        return max(1, int(self.get("peer_db", "tier2_loss_threshold", default=20)))

    # ── Tier 3 ────────────────────────────────────────────────────────────────

    @property
    def tier3_ramp_step_mbps(self) -> float:
        return max(0.01, float(self.get("peer_db", "tier3_ramp_step_mbps", default=0.05)))

    @property
    def tier3_ramp_interval_sec(self) -> float:
        return max(0.1, float(self.get("peer_db", "tier3_ramp_interval_sec", default=10.0)))

    @property
    def tier3_ramp_step_down_mbps(self) -> float:
        return max(0.0, float(self.get("peer_db", "tier3_ramp_step_down_mbps", default=0.1)))

    @property
    def tier3_loss_threshold(self) -> int:
        return max(1, int(self.get("peer_db", "tier3_loss_threshold", default=24)))

    # ── Shared peer_db params ─────────────────────────────────────────────────

    @property
    def loss_floor_ratio(self) -> float:
        return max(0.0, min(1.0, float(self.get("peer_db", "loss_floor_ratio", default=0.5))))

    @property
    def ramp_ceiling_mbps(self) -> float:
        return max(1.0, float(self.get("peer_db", "ramp_ceiling_mbps", default=4500.0)))
