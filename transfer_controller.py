"""
transfer_controller.py — TransferController: orchestration layer.

Sits between main.py (or future GUI) and the FileSender / FileReceiver.
Responsibilities:
  • Configure logging based on config.json settings
  • Instantiate and wire up sender / receiver
  • Report progress and final status to caller
  • Phase 2: exposes num_streams from config for callers that need it

Usage:
    ctrl = TransferController()
    # Send
    ok = ctrl.send("/path/to/file.bin", host="192.168.1.10", port=9000)
    # Receive
    path = ctrl.receive(output_dir="/tmp/received", port=9000)
"""

import logging
import os
import re
import sys
import time
from typing import Optional

import peer_db
from config import Config
from receiver import FileReceiver
from sender import FileSender

logger = logging.getLogger(__name__)

_PROGRESS_RE = re.compile(r"^\[(PROGRESS|PACING)\]")

_FMT_NAMED  = "%(asctime)s  %(levelname)-8s  %(name)s — %(message)s"
_FMT_BARE   = "%(asctime)s  %(levelname)-8s  %(message)s"
_DATEFMT    = "%H:%M:%S"


class _ProgressAwareFormatter(logging.Formatter):
    """Use a name-free format for progress/pacing lines; named format for all others."""

    def __init__(self) -> None:
        super().__init__()
        self._named = logging.Formatter(_FMT_NAMED, datefmt=_DATEFMT)
        self._bare  = logging.Formatter(_FMT_BARE,  datefmt=_DATEFMT)

    def format(self, record: logging.LogRecord) -> str:
        if _PROGRESS_RE.match(record.getMessage()):
            return self._bare.format(record)
        return self._named.format(record)


class TransferController:
    """
    High-level transfer orchestrator.

    Args:
        config_path: path to config.json (default "config.json")
    """

    def __init__(self, config_path: str = "config.json") -> None:
        self._cfg = Config(config_path)
        self._scaling_hook: Optional[object] = None
        self._scaling_hook_interval_s: float = 5.0
        self._peer_reset_hook: Optional[object] = None
        self._configure_logging()
        # Initialise peer DB and eagerly resolve the local identity key before
        # any threads start, preventing a write-on-first-use race on Windows.
        peer_db.init(self._cfg.peer_db_path)
        self._local_mac_key: str = peer_db.get_local_key()

    # ── public API ────────────────────────────────────────────────────────────

    def set_peer_reset_hook(self, hook) -> None:
        """
        Register a hook called after the receiver's mac_key is identified,
        before the transfer profile is selected.

        hook signature: (peer: dict) -> bool
            peer keys: mac_key, tier, send_count, first_seen, last_seen
            return True  → stats were reset (sender will use tier 0)
            return False → no reset, proceed with existing profile
        """
        self._peer_reset_hook = hook

    def set_scaling_hook(
        self,
        hook,
        probe_interval_s: float = 5.0,
    ) -> None:
        """
        Register a scaling hook consulted by StreamManager during transfers.

        hook signature: (StreamManager) -> ScalingDecision
        Phase 3: advisory only — logged but no live stream resize.
        """
        self._scaling_hook            = hook
        self._scaling_hook_interval_s = probe_interval_s
        logger.info("TransferController: scaling hook registered")

    def send(
        self,
        filepath: str,
        host: str,
        port: Optional[int] = None,
    ) -> bool:
        """
        Send *filepath* to *host*:*port* using num_streams parallel UDP streams.

        Returns True on verified successful delivery.
        """
        dest_port   = port if port is not None else self._cfg.base_port
        num_streams = self._cfg.num_streams

        logger.info(
            "TransferController.send: %r → %s:%d  (%d streams)",
            filepath, host, dest_port, num_streams,
        )
        t0     = time.monotonic()
        sender = FileSender(self._cfg)
        if self._scaling_hook is not None:
            sender.set_scaling_hook(
                self._scaling_hook, self._scaling_hook_interval_s
            )

        if self._peer_reset_hook is not None:
            sender.set_peer_reset_hook(self._peer_reset_hook)

        try:
            ok = sender.send_file(filepath, dest_host=host, dest_port=dest_port,
                                  local_mac_key=self._local_mac_key)
        except FileNotFoundError as exc:
            logger.error("Send aborted: %s", exc)
            return False
        except Exception as exc:
            logger.exception("Unexpected error during send: %s", exc)
            return False

        elapsed = time.monotonic() - t0
        size    = os.path.getsize(filepath) if os.path.isfile(filepath) else 0
        if ok:
            mbps = (size / elapsed / 1_048_576) if elapsed > 0 else 0
            logger.info(
                "Send SUCCESS — %.1f MB in %.2f s = %.1f MB/s  (%d streams)",
                size / 1_048_576, elapsed, mbps, num_streams,
            )
        else:
            logger.error("Send FAILED after %.2f s", elapsed)
        return ok

    def receive(
        self,
        output_dir: str = ".",
        port: Optional[int] = None,
    ) -> str:
        """
        Block and receive one file into *output_dir*.

        Returns the absolute path of the received file.
        Raises RuntimeError on unrecoverable failure.
        """
        listen_port = port if port is not None else self._cfg.base_port
        logger.info(
            "TransferController.receive: listening on port %d → %r",
            listen_port, output_dir,
        )
        t0   = time.monotonic()
        recv = FileReceiver(self._cfg)

        try:
            final_path = recv.receive_file(output_dir=output_dir, bind_port=listen_port,
                                           local_mac_key=self._local_mac_key)
        except RuntimeError as exc:
            logger.error("Receive FAILED: %s", exc)
            raise
        except Exception as exc:
            logger.exception("Unexpected error during receive: %s", exc)
            raise RuntimeError(str(exc)) from exc

        elapsed = time.monotonic() - t0
        size    = os.path.getsize(final_path) if os.path.isfile(final_path) else 0
        mbps    = (size / elapsed / 1_048_576) if elapsed > 0 else 0
        logger.info(
            "Receive SUCCESS — %r  %.1f MB in %.2f s = %.1f MB/s",
            final_path, size / 1_048_576, elapsed, mbps,
        )
        return final_path

    # ── logging ───────────────────────────────────────────────────────────────

    def _configure_logging(self) -> None:
        level = getattr(logging, self._cfg.log_level, logging.INFO)
        fmt   = _ProgressAwareFormatter()

        handlers = [logging.StreamHandler(sys.stdout)]
        if self._cfg.log_to_file:
            handlers.append(logging.FileHandler(self._cfg.log_file, encoding="utf-8"))

        for h in handlers:
            h.setFormatter(fmt)

        logging.basicConfig(level=level, handlers=handlers)
        logging.getLogger("asyncio").setLevel(logging.WARNING)
        self._log_pacing_config()

    def _log_pacing_config(self) -> None:
        """Log the active step-climb pacing configuration at startup."""
        cfg = self._cfg
        logger.info("Pacing: step-climb  initial=%.0f MB/s  loss_threshold=%d",
                    cfg.initial_rate_mbps, cfg.loss_threshold)
        logger.info(
            "Pacing: COARSE +%.0f MB/s / %.1fs  "
            "FINE +%.1f MB/s / %.1fs  "
            "MICRO +%.3f MB/s / %.1fs  "
            "HOLD probe / %.1fs",
            cfg.coarse_step_mbps, cfg.coarse_interval_s,
            cfg.fine_step_mbps,   cfg.fine_interval_s,
            cfg.micro_step_mbps,  cfg.micro_interval_s,
            cfg.hold_interval_s,
        )
        logger.info(
            "Pacing: min=%.0f MB/s  rate_hint=%.0f MB/s (%s)  "
            "streams=%d  chunk=%d B",
            cfg.min_rate_mbps,
            cfg.rate_hint_mbps,
            "cap active" if cfg.rate_hint_mbps > 0 else "unlimited",
            cfg.num_streams,
            cfg.chunk_size,
        )
