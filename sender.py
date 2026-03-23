"""
sender.py — FileSender: multi-stream UDP file sender.

Phase 4 additions:
  Port layout:
    9000 — Control : INIT, META, FINISH, COMPLETE, RATE_HINT(sender→recv)
    9001 — Feedback: sender binds/listens for NACK, THROUGHPUT_REPORT,
                      RATE_HINT(recv→sender), RESEND
    9002–9005 — Data : 4 streams

  Feedback listener thread (runs on 9001 throughout transfer):
    THROUGHPUT_REPORT → pacing.update_stable(rate_mbps)
                         stable_mbps now reflects true end-to-end delivery rate
    NACK              → accumulated into nack_set for NACK pass
    RATE_HINT         → pacing.set_rate_hint_cap(max_mbps)
    RESEND            → forwarded to resend_queue for FINISH loop

  NACK pass (after initial pass, before FINISH):
    1. Initial pass completes (work_queue.join())
    2. Wait 1s for late NACKs from receiver processing pipeline
    3. Drain nack_set → run retransmit pass for failed chunks
    4. Send FINISH

  RATE_HINT to receiver:
    Sent on control channel (9000) after META ACK.
    Receiver stores it for future use (Phase 5+).

Peer-DB / adaptive ramp (per-peer pacing memory):
  At session open, receiver_mac_key is extracted from the INIT ACK payload
  (bytes 1–32).  get_best_stable_mbps() is used to build a RampProfile:
    — known peer  → start at recorded stable speed
    — unknown     → start at config.unknown_ramp_start_mbps
  profile.start_mbps is passed as initial_rate_mbs to AdaptivePacingController.
  The 4-phase step-climb engine then runs normally from that starting point.
  write_result() is called on both success and failure paths.
"""

import json
import logging
import math
import os
import queue
import threading
import time
from typing import List, Optional, Set

import peer_db
from config import Config
from crypto import CryptoEngine
from integrity import compute_file_sha256, format_hex
from pacing import AdaptivePacingController, LOSS_THRESHOLD
from protocol import (
    PacketType, build_packet, parse_packet,
    build_init_payload, build_meta_payload, build_data_payload,
    build_finish_payload, build_rate_hint_payload, build_loss_report_payload,
    parse_ack_payload, parse_complete_payload, parse_resend_payload,
    parse_nack_payload, parse_throughput_report_payload, parse_rate_hint_payload,
)
from ramp_profile import RampProfile
from rate_limiter import RateLimiter
from stream_manager import StreamManager
from transport import UDPTransport

logger = logging.getLogger(__name__)

_WSAENOBUFS = 10055


class FileSender:

    def __init__(self, config: Config) -> None:
        self._cfg          = config
        self._crypto       = CryptoEngine(enabled=config.crypto_enabled)
        self._rate_limiter = RateLimiter(
            send_limit_mbps=(config.send_limit_mbps if config.rate_limiter_enabled else 0.0),
        )
        self._scaling_hook: Optional[object] = None
        self._scaling_hook_interval_s: float = 5.0
        self._peer_reset_hook: Optional[object] = None

    def set_scaling_hook(self, hook, probe_interval_s: float = 5.0) -> None:
        """Register a scaling hook forwarded to StreamManager on next send_file call."""
        self._scaling_hook = hook
        self._scaling_hook_interval_s = probe_interval_s

    def set_peer_reset_hook(self, hook) -> None:
        """
        Register a hook invoked after the receiver's mac_key is extracted from
        the INIT ACK, before the ramp-profile tier is selected.

        hook(peer: dict) -> bool
        If the hook returns True the peer's send record has been reset and the
        tier selection will start fresh from tier 0.
        """
        self._peer_reset_hook = hook

    def send_file(self, filepath: str, dest_host: str, dest_port: int,
                  local_mac_key: str = "") -> bool:
        if not os.path.isfile(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")

        file_size    = os.path.getsize(filepath)
        filename     = os.path.basename(filepath)
        chunk_size   = self._cfg.chunk_size
        total_chunks = max(1, math.ceil(file_size / chunk_size))
        num_streams  = self._cfg.num_streams
        buf_size     = self._cfg.socket_buffer_size
        feedback_port = dest_port + 1    # 9001 — sender binds/listens
        data_base     = dest_port + 2    # 9002..9005

        # SHA decision is deferred until after META ACK so we can read
        # the receiver's hash_requested flag (byte 1 of ACK payload).
        # We send META with a placeholder zero hash, then compute the real
        # hash if the negotiation outcome requires it, then start streams.
        _ZERO_SHA   = bytes(32)
        sha_elapsed = 0.0
        sha_speed   = 0.0

        logger.info("=" * 60)
        logger.info("FileSender  [Phase 4 — Feedback Channel]")
        logger.info("  File         : %r", filename)
        logger.info("  Size         : %d bytes  (%d chunks × %d B)", file_size, total_chunks, chunk_size)
        logger.info("  Control port : %d", dest_port)
        logger.info("  Feedback port: %d (sender listens)", feedback_port)
        logger.info("  Data ports   : %d–%d", data_base, data_base + num_streams - 1)
        logger.info("  Initial rate : %.1f MB/s", self._cfg.initial_rate_mbps)
        logger.info("  Rate hint    : %.1f MB/s (%s)",
                    self._cfg.rate_hint_mbps,
                    "cap active" if self._cfg.rate_hint_mbps > 0 else "no cap")
        logger.info("  hash_disabled: %s  hash_required: %s",
                    self._cfg.hash_disabled, self._cfg.hash_required)
        logger.info("=" * 60)

        session_id = os.urandom(16)

        with UDPTransport(("", 0), buffer_size=buf_size) as ctrl:
            with UDPTransport(("", feedback_port), buffer_size=buf_size) as feedback:
                dest_ctrl = (dest_host, dest_port)

                # ── INIT handshake — include local mac_key ────────────────────
                init_ack = self._handshake_with_ack(
                    ctrl, session_id, dest_ctrl,
                    build_packet(PacketType.INIT, session_id, 0,
                                 build_init_payload(1, num_streams, local_mac_key)),
                    PacketType.INIT, "INIT",
                )
                if init_ack is None:
                    return False

                # Extract receiver's mac_key from INIT ACK extended payload.
                # Layout: [0] ack_type  [1:33] receiver_mac_key (32 ASCII bytes)
                # Falls back to "" when talking to an old receiver.
                receiver_mac_key = ""
                if len(init_ack.payload) >= 33:
                    try:
                        receiver_mac_key = init_ack.payload[1:33].decode("ascii")
                    except (UnicodeDecodeError, ValueError):
                        pass

                if receiver_mac_key:
                    peer_db.upsert_peer(receiver_mac_key)
                    logger.info("Peer identified  receiver_key=%s…", receiver_mac_key[:8])
                    if self._peer_reset_hook is not None:
                        peer = peer_db.find_peer(receiver_mac_key)
                        if peer is not None:
                            self._peer_reset_hook(peer)
                else:
                    logger.info("Peer did not send mac_key — DB lookup skipped")

                # ── META handshake — read receiver's hash preference ──────────
                # Send META with zero hash placeholder; we'll compute the real
                # hash after negotiation if required.
                meta_ack = self._handshake_with_ack(
                    ctrl, session_id, dest_ctrl,
                    build_packet(PacketType.META, session_id, 0,
                                 build_meta_payload(filename, file_size, total_chunks,
                                                    chunk_size, _ZERO_SHA)),
                    PacketType.META, "META",
                )
                if meta_ack is None:
                    return False

                # Read receiver's hash_requested flag (byte 1 of ACK payload)
                _receiver_hash_requested = (
                    len(meta_ack.payload) >= 2 and bool(meta_ack.payload[1] & 0x01)
                )
                logger.info(
                    "META ACK received  receiver_hash_requested=%s",
                    "yes" if _receiver_hash_requested else "no",
                )

                # ── SHA negotiation ────────────────────────────────────────────
                # hash_disabled → never compute (sender's veto)
                # hash_required → always compute (sender forces it)
                # neither       → compute only if receiver requested it
                _do_hash = (
                    not self._cfg.hash_disabled
                    and (self._cfg.hash_required or _receiver_hash_requested)
                )

                if _do_hash:
                    reason = ("required by sender" if self._cfg.hash_required
                              else "requested by receiver")
                    logger.info("Computing file SHA-256 (%s) …", reason)
                    _sha_t0     = time.monotonic()
                    file_sha256 = compute_file_sha256(filepath)
                    sha_elapsed = time.monotonic() - _sha_t0
                    sha_speed   = (file_size / sha_elapsed / 1_048_576
                                   if sha_elapsed > 0 else 0.0)
                    logger.info(
                        "SHA-256: %s  (%.2fs at %.1f MB/s)",
                        format_hex(file_sha256), sha_elapsed, sha_speed,
                    )
                    # Resend META with real hash so receiver can verify
                    if not self._handshake(
                        ctrl, session_id, dest_ctrl,
                        build_packet(PacketType.META, session_id, 0,
                                     build_meta_payload(filename, file_size, total_chunks,
                                                        chunk_size, file_sha256)),
                        PacketType.META, "META (with hash)",
                    ):
                        return False
                else:
                    file_sha256 = _ZERO_SHA
                    if self._cfg.hash_disabled:
                        logger.info("SHA-256 disabled by sender config")
                    else:
                        logger.info("SHA-256 not requested by receiver — skipping")

                ctrl.send(
                    build_packet(PacketType.RATE_HINT, session_id, 0,
                                 build_rate_hint_payload(self._cfg.rate_hint_mbps)),
                    dest_ctrl,
                )
                logger.info(
                    "RATE_HINT → receiver  max=%.1f MB/s (%s)",
                    self._cfg.rate_hint_mbps,
                    "advisory" if self._cfg.rate_hint_mbps == 0 else "cap",
                )

                data_transports: List[UDPTransport] = []
                try:
                    for i in range(num_streams):
                        dt = UDPTransport(("", 0), buffer_size=buf_size)
                        data_transports.append(dt)
                        logger.info(
                            "Stream-%d: local port %d → %s:%d  "
                            "(SO_SNDBUF=%d MB)",
                            i, dt.bound_port, dest_host, data_base + i,
                            dt.sndbuf_mb,
                        )

                    return self._run_transfer(
                        ctrl, feedback, data_transports, session_id,
                        dest_host, dest_port, data_base, filepath,
                        file_size, total_chunks, chunk_size, file_sha256,
                        sha_elapsed=sha_elapsed, sha_speed=sha_speed,
                        do_hash=_do_hash,
                        receiver_mac_key=receiver_mac_key,
                    )
                finally:
                    for dt in data_transports:
                        dt.close()

    # ── Handshake helper ──────────────────────────────────────────────────────

    def _handshake(self, ctrl, session_id, dest, pkt, expected_ack, name) -> bool:
        return self._handshake_with_ack(ctrl, session_id, dest, pkt,
                                        expected_ack, name) is not None

    def _handshake_with_ack(self, ctrl, session_id, dest, pkt, expected_ack, name):
        """
        Like _handshake but returns the full ACK Packet on success (or None on
        failure) so callers can inspect extended payload bytes.
        """
        for attempt in range(1, self._cfg.max_retries + 1):
            ctrl.send(pkt, dest)
            logger.debug("%s → %s:%d  (attempt %d/%d)",
                         name, dest[0], dest[1], attempt, self._cfg.max_retries)
            deadline = time.monotonic() + self._cfg.ack_timeout
            while time.monotonic() < deadline:
                result = ctrl.recv(timeout=min(1.0, deadline - time.monotonic()))
                if result is None:
                    break
                data, _ = result
                p = parse_packet(data)
                if p is None or p.session_id != session_id:
                    continue
                if p.ptype == PacketType.ACK:
                    try:
                        if parse_ack_payload(p.payload) == expected_ack:
                            logger.info("%s ACK received", name)
                            return p          # ← full packet for inspection
                    except ValueError:
                        pass
                elif p.ptype == PacketType.ERROR:
                    logger.error("%s: ERROR from receiver", name)
                    return None
        logger.error("%s: no ACK after %d attempts", name, self._cfg.max_retries)
        return None

    # ── Transfer core ─────────────────────────────────────────────────────────

    def _run_transfer(
        self,
        ctrl: UDPTransport,
        feedback: UDPTransport,
        data_transports: List[UDPTransport],
        session_id: bytes,
        dest_host: str,
        dest_port: int,
        data_base: int,
        filepath: str,
        file_size: int,
        total_chunks: int,
        chunk_size: int,
        file_sha256: bytes,
        sha_elapsed: float = 0.0,
        sha_speed: float = 0.0,
        do_hash: bool = False,
        receiver_mac_key: str = "",
    ) -> bool:
        num_streams = len(data_transports)

        # ── 4-tier ramp profile selection ─────────────────────────────────────
        # Tier 0: peer never seen                  → cold-start default
        # Tier 1: send_count  1–9                  → avg_stable_mbps, gentle step-down
        # Tier 2: send_count 10–19                 → conservative micro-probe
        # Tier 3: send_count ≥ 20                  → very fine probing, well-characterised
        # Cross-direction fallback: if only recv history exists, use it as a
        # symmetric proxy (role reversal).
        cfg = self._cfg
        send_count = peer_db.get_peer_send_count(receiver_mac_key) if receiver_mac_key else 0

        if send_count == 0:
            tier = 0
            profile = RampProfile(
                start_mbps     = cfg.unknown_ramp_start_mbps,
                step_mbps      = cfg.tier0_ramp_step_mbps,
                interval_sec   = cfg.tier0_ramp_interval_sec,
                step_down_mbps = cfg.tier0_ramp_step_down_mbps,
                loss_threshold = cfg.tier0_loss_threshold,
            )
        elif send_count < 10:
            tier = 1
            avg = peer_db.get_avg_stable_mbps(receiver_mac_key, "send")
            if avg is None:
                avg = peer_db.get_best_stable_mbps(receiver_mac_key) or cfg.unknown_ramp_start_mbps
            profile = RampProfile(
                start_mbps     = avg,
                step_mbps      = cfg.tier1_ramp_step_mbps,
                interval_sec   = cfg.tier1_ramp_interval_sec,
                step_down_mbps = cfg.tier1_ramp_step_down_mbps,
                loss_threshold = cfg.tier1_loss_threshold,
            )
        elif send_count < 20:
            tier = 2
            avg = peer_db.get_avg_stable_mbps(receiver_mac_key, "send")
            if avg is None:
                avg = peer_db.get_best_stable_mbps(receiver_mac_key) or cfg.unknown_ramp_start_mbps
            profile = RampProfile(
                start_mbps     = avg,
                step_mbps      = cfg.tier2_ramp_step_mbps,
                interval_sec   = cfg.tier2_ramp_interval_sec,
                step_down_mbps = cfg.tier2_ramp_step_down_mbps,
                loss_threshold = cfg.tier2_loss_threshold,
            )
        else:
            tier = 3
            avg = peer_db.get_avg_stable_mbps(receiver_mac_key, "send")
            if avg is None:
                avg = peer_db.get_best_stable_mbps(receiver_mac_key) or cfg.unknown_ramp_start_mbps
            profile = RampProfile(
                start_mbps     = avg,
                step_mbps      = cfg.tier3_ramp_step_mbps,
                interval_sec   = cfg.tier3_ramp_interval_sec,
                step_down_mbps = cfg.tier3_ramp_step_down_mbps,
                loss_threshold = cfg.tier3_loss_threshold,
            )

        logger.info(
            "RampProfile [tier=%d  sends=%d]  start=%.1f MB/s  "
            "step=%.2f MB/s  interval=%.1fs  step_down=%.2f MB/s  loss_threshold=%d",
            tier, send_count,
            profile.start_mbps, profile.step_mbps, profile.interval_sec,
            profile.step_down_mbps, profile.loss_threshold,
        )

        # Loss callback: Tiers 1–3 apply an additional per-tier step-down after
        # each phase transition.  Tier 0 uses None so the state machine runs
        # exactly as before (no extra step-down on first-time peers).
        if tier > 0 and profile.step_down_mbps > 0:
            _floor = profile.start_mbps * cfg.loss_floor_ratio
            _step_down = profile.step_down_mbps
            def _loss_cb(post_transition_mbps: float) -> float:
                return max(post_transition_mbps - _step_down, _floor)
        else:
            _loss_cb = None

        pacing = AdaptivePacingController(
            num_streams=num_streams,
            chunk_size=chunk_size,
            loss_threshold=profile.loss_threshold,
            initial_rate_mbs=profile.start_mbps,
            min_rate_mbs=cfg.min_rate_mbps,
            coarse_step_mbs=profile.step_mbps,
            fine_step_mbs=cfg.fine_step_mbps,
            micro_step_mbs=cfg.micro_step_mbps,
            coarse_interval_s=cfg.coarse_interval_s,
            fine_interval_s=cfg.fine_interval_s,
            micro_interval_s=cfg.micro_interval_s,
            hold_interval_s=cfg.hold_interval_s,
            loss_event_callback=_loss_cb,
        )

        # Apply sender's own rate_hint_mbps as initial cap (0 = no cap)
        if self._cfg.rate_hint_mbps > 0:
            pacing.set_rate_hint_cap(self._cfg.rate_hint_mbps)

        # ── StreamManager (owns stream workers and work queue) ────────────────
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
        try:
            # Phase 4: NACK accumulation
            nack_set:  Set[int]    = set()
            nack_lock: threading.Lock = threading.Lock()

            # Phase 4: RESEND packets from feedback channel
            resend_feedback_queue: queue.Queue = queue.Queue()

            transfer_t0      = time.monotonic()
            stop_reporter    = threading.Event()
            stop_feedback    = threading.Event()
            resend_pass_live = [0]

            # Peak target rate reached during the transfer (high-water mark).
            # Used by write_result() — updated inside the pacing reporter thread.
            peak_mbps = [profile.start_mbps]

            # ── Feedback listener thread ──────────────────────────────────────────

            def feedback_listener() -> None:
                """
                Runs on 9001 throughout the transfer.

                THROUGHPUT_REPORT → pacing.update_stable()  [drives stable_mbps]
                NACK              → nack_set.add()           [NACK pass after initial]
                RATE_HINT         → pacing.set_rate_hint_cap()
                RESEND            → resend_feedback_queue    [FINISH loop]
                """
                while not stop_feedback.is_set():
                    result = feedback.recv(timeout=0.5)
                    if result is None:
                        continue
                    data, addr = result
                    pkt = parse_packet(data)
                    if pkt is None or pkt.session_id != session_id:
                        continue

                    if pkt.ptype == PacketType.THROUGHPUT_REPORT:
                        try:
                            report = parse_throughput_report_payload(pkt.payload)
                            wms    = report["window_ms"]
                            bw     = report["bytes_window"]
                            if wms > 0 and bw >= 0:
                                rate_mbps = bw / wms * 1_000 / 1_048_576
                                pacing.update_stable(rate_mbps)
                                logger.debug(
                                    "THROUGHPUT_REPORT: %.1f MB/s  "
                                    "%d chunks  window=%dms",
                                    rate_mbps, report["chunks_total"], wms,
                                )
                        except Exception as exc:
                            logger.debug("THROUGHPUT_REPORT parse error: %s", exc)

                    elif pkt.ptype == PacketType.NACK:
                        try:
                            chunk_id = parse_nack_payload(pkt.payload)
                            with nack_lock:
                                nack_set.add(chunk_id)
                            logger.debug("NACK received for chunk %d", chunk_id)
                        except Exception as exc:
                            logger.debug("NACK parse error: %s", exc)

                    elif pkt.ptype == PacketType.RATE_HINT:
                        try:
                            max_rate = parse_rate_hint_payload(pkt.payload)
                            if max_rate > 0:
                                pacing.set_rate_hint_cap(max_rate)
                        except Exception as exc:
                            logger.debug("RATE_HINT parse error: %s", exc)

                    elif pkt.ptype == PacketType.RESEND:
                        try:
                            chunk_ids = parse_resend_payload(pkt.payload)
                            if chunk_ids:
                                resend_feedback_queue.put(chunk_ids)
                        except Exception as exc:
                            logger.debug("RESEND parse error: %s", exc)

            feedback_thread = threading.Thread(
                target=feedback_listener, daemon=True, name="FeedbackListener"
            )
            feedback_thread.start()
            logger.info("FeedbackListener started on port %d", feedback.bound_port)

            # ── Pacing reporter thread ─────────────────────────────────────────────

            def _pacing_reporter() -> None:
                report_interval = self._cfg.progress_interval_ms / 1_000.0
                while not stop_reporter.wait(timeout=report_interval):
                    now        = time.monotonic()
                    target     = pacing.target_mbps
                    stable     = pacing.stable_rate_mbps
                    total_sent = sum(mgr.live_sent)
                    pct        = (total_sent / total_chunks * 100.0) if total_chunks else 0.0
                    remaining  = total_chunks - total_sent

                    # Track peak target rate for write_result()
                    if target > peak_mbps[0]:
                        peak_mbps[0] = target

                    elapsed_total = now - transfer_t0
                    overall       = (total_sent * chunk_size / 1_048_576 / elapsed_total
                                     if elapsed_total > 0 else 0.0)
                    eta_s = ((remaining * chunk_size / 1_048_576) / overall
                             if overall > 0 else float("inf"))
                    eta_str = f"{eta_s:.0f}s" if eta_s < 86_400 else "∞"

                    logger.info(
                        "[PROGRESS-TX] %d/%d (%.1f%%)  "
                        "target=%.1f  "
                        "ETA=%s  resend=%d",
                        total_sent, total_chunks, pct,
                        target,
                        eta_str, resend_pass_live[0],
                    )
                    logger.info(
                        "[PACING] current=%.1f  stable=%.1f  lost chunks=%d",
                        target, stable, sum(mgr.live_nobufs),
                    )
                    for sid in range(num_streams):
                        logger.debug("[STREAM %d] sent=%d  nobufs=%d",
                                     sid, mgr.live_sent[sid], mgr.live_nobufs[sid])

            reporter_thread = threading.Thread(target=_pacing_reporter, daemon=True, name="PacingReporter")
            reporter_thread.start()
            logger.info(
                "%d stream workers started  start_rate=%s  tier=%d  loss_threshold=%d",
                num_streams, pacing.tier_name, tier, profile.loss_threshold,
            )

            # ── Per-pass loss tracking ────────────────────────────────────────────
            # Accumulated list of dicts written to transfer_loss_passes at the end.
            pass_records: list = []

            # ── Initial send pass ─────────────────────────────────────────────────

            initial_pass_elapsed = mgr.enqueue_pass(list(range(total_chunks)), "Initial pass")

            # Stop reporter before FINISH loop (no more data flowing)
            stop_reporter.set()
            reporter_thread.join(timeout=2.0)

            # ── NACK pass ─────────────────────────────────────────────────────────
            logger.info("Waiting 1s for late NACKs from receiver pipeline …")
            time.sleep(1.0)

            with nack_lock:
                nack_list = sorted(nack_set)
                nack_set.clear()

            if nack_list:
                logger.info(
                    "NACK pass: %d chunks failed SHA-256 on receiver — retransmitting …",
                    len(nack_list),
                )
                mgr.enqueue_pass(nack_list, "NACK pass")
            else:
                logger.info("NACK pass: no failures reported by receiver")

            # finish_rate_mbs is the anchor for ALL resend pass caps.
            # Every resend pass caps at finish_rate_mbs × 80% — the cap does
            # NOT compound across passes.
            #
            # CRITICAL: use min(target, stable) not just target.
            # If the initial pass ended while the step-climb was still probing
            # (e.g. FINE phase at 303 MB/s) but the switch was silently dropping
            # 55% of packets, target is a speculative value the network never
            # confirmed.  stable_rate_mbps reflects what the receiver actually
            # absorbed (~113 MB/s in that case).  Anchoring resends at 303 × 80%
            # = 242 MB/s would flood the same broken rate again every pass.
            # Anchoring at min(303, 113) × 80% = 90 MB/s sends at a rate the
            # receiver has actually demonstrated it can handle.
            _target_at_finish = pacing.target_mbps
            _stable_at_finish = pacing.stable_rate_mbps
            finish_rate_mbs   = min(_target_at_finish, _stable_at_finish)
            if _stable_at_finish < _target_at_finish * 0.75:
                logger.warning(
                    "Resend anchor clamped to stable rate: "
                    "target=%.1f MB/s  stable=%.1f MB/s  "
                    "anchor=%.1f MB/s  "
                    "(target was speculative — switch was silently dropping packets)",
                    _target_at_finish, _stable_at_finish, finish_rate_mbs,
                )

            # ── FINISH / RESEND / COMPLETE cycle ──────────────────────────────────

            finish_pkt   = build_packet(
                PacketType.FINISH, session_id, 0,
                build_finish_payload(total_chunks, file_sha256),
            )
            dest_ctrl    = (dest_host, dest_port)
            ack_timeout  = self._cfg.ack_timeout
            recv_timeout = self._cfg.recv_timeout
            max_retries  = self._cfg.max_retries
            resend_pass  = 0
            overall_deadline = time.monotonic() + recv_timeout
            empty_windows    = 0

            while time.monotonic() < overall_deadline:
                ctrl.send(finish_pkt, dest_ctrl)
                logger.info(
                    "FINISH sent  resend_pass=%d  rate=%s  silent=%d/%d",
                    resend_pass, pacing.tier_name, empty_windows, max_retries,
                )

                batch_deadline = time.monotonic() + ack_timeout
                all_missing: List[int] = []
                got_complete    = False
                complete_pkt_p  = None
                got_finish_ack  = False

                while time.monotonic() < batch_deadline:
                    remaining = batch_deadline - time.monotonic()
                    if remaining <= 0:
                        break

                    # Listen on control for COMPLETE and FINISH-ACK
                    result = ctrl.recv(timeout=min(0.2, remaining))
                    if result is not None:
                        data, _ = result
                        p = parse_packet(data)
                        if p is not None and p.session_id == session_id:
                            if p.ptype == PacketType.COMPLETE:
                                got_complete   = True
                                complete_pkt_p = p
                                break
                            if p.ptype == PacketType.ACK:
                                try:
                                    if parse_ack_payload(p.payload) == PacketType.FINISH:
                                        got_finish_ack = True
                                        empty_windows  = 0
                                        batch_deadline = time.monotonic() + ack_timeout
                                        # Read optional status string from bytes 1+
                                        # of the ACK payload (receiver reports its
                                        # current activity).  Falls back to a generic
                                        # message on old receivers that don't send it.
                                        if len(p.payload) > 1:
                                            _status = p.payload[1:].decode(
                                                "utf-8", errors="replace"
                                            )
                                        else:
                                            _status = "Receiver: post-transfer processing …"
                                        logger.info("FINISH-ACK — %s", _status)
                                except ValueError:
                                    pass

                    # Drain RESEND packets from feedback queue (arrives on 9001)
                    while True:
                        try:
                            batch = resend_feedback_queue.get_nowait()
                            all_missing.extend(batch)
                        except queue.Empty:
                            break

                # ── Act on collected responses ─────────────────────────────────────
                if got_complete:
                    mgr_stats     = mgr.stop()
                    stream_sent   = [s.sent   for s in mgr_stats]
                    stream_nobufs = [s.nobufs for s in mgr_stats]
                    stop_feedback.set()
                    feedback_thread.join(timeout=2.0)
                    total_nobufs = sum(stream_nobufs)
                    if total_nobufs:
                        logger.info("Total WSAENOBUFS: %d", total_nobufs)
                    logger.info(
                        "Stream workers stopped.  sent=%s  nobufs=%s  final_rate=%s",
                        stream_sent, stream_nobufs, pacing.tier_name,
                    )

                    status = parse_complete_payload(complete_pkt_p.payload)
                    total_elapsed = time.monotonic() - transfer_t0
                    filename      = os.path.basename(filepath)

                    # actual send speed = file_size / initial pass time only
                    actual_mbps = (file_size / initial_pass_elapsed / 1_048_576
                                   if initial_pass_elapsed > 0 else 0.0)
                    # net speed = file_size / (SHA + transfer + resends)
                    # sha_elapsed is 0.0 when hashing was skipped/disabled
                    net_total = total_elapsed + sha_elapsed
                    net_mbps = (file_size / net_total / 1_048_576
                                if net_total > 0 else 0.0)

                    # Final pass record (clean delivery — chunks_lost=0)
                    pass_records.append({
                        "pass_index":        resend_pass,
                        "chunks_sent":       total_chunks,
                        "chunks_lost":       0,
                        "pass_duration_sec": total_elapsed,
                    })
                    # Final LOSS_REPORT to receiver (chunks_lost=0 signals success)
                    ctrl.send(
                        build_packet(
                            PacketType.LOSS_REPORT, session_id, 0,
                            build_loss_report_payload(
                                pass_index        = resend_pass,
                                chunks_sent       = total_chunks,
                                chunks_lost       = 0,
                                current_mbps      = pacing.target_mbps,
                                tier              = tier,
                                pass_duration_sec = total_elapsed,
                            ),
                        ),
                        dest_ctrl,
                    )

                    if status == 0:
                        self._print_summary(
                            filename=filename,
                            success=True,
                            fail_reason="",
                            sha_enabled=do_hash,
                            sha_elapsed=sha_elapsed,
                            sha_speed=sha_speed,
                            loss_events=total_nobufs,
                            actual_mbps=actual_mbps,
                            net_mbps=net_mbps,
                            direction="send",
                        )
                        transfer_id = peer_db.write_result(
                            receiver_mac_key, "send",
                            profile.start_mbps, peak_mbps[0],
                            pacing.stable_rate_mbps,
                            file_sha256.hex(), total_elapsed, success=1,
                            avg_mbps=net_mbps,
                            max_mbps=peak_mbps[0],
                            tier=tier,
                        )
                        peer_db.write_loss_passes(transfer_id, pass_records)
                        self._write_metrics(
                            session_id, filepath, file_size, total_chunks, chunk_size,
                            num_streams, transfer_t0, resend_pass, stream_sent,
                            stream_nobufs, pacing, success=True,
                        )
                        return True

                    label = {1: "SHA-256 mismatch", 2: "receiver error"}.get(status, f"status={status}")
                    self._print_summary(
                        filename=filename,
                        success=False,
                        fail_reason=label,
                        sha_enabled=do_hash,
                        sha_elapsed=sha_elapsed,
                        sha_speed=sha_speed,
                        loss_events=total_nobufs,
                        actual_mbps=actual_mbps,
                        net_mbps=net_mbps,
                        direction="send",
                    )
                    transfer_id = peer_db.write_result(
                        receiver_mac_key, "send",
                        profile.start_mbps, peak_mbps[0],
                        pacing.stable_rate_mbps,
                        file_sha256.hex(), total_elapsed, success=0,
                        avg_mbps=net_mbps, max_mbps=peak_mbps[0], tier=tier,
                    )
                    peer_db.write_loss_passes(transfer_id, pass_records)
                    self._write_metrics(
                        session_id, filepath, file_size, total_chunks, chunk_size,
                        num_streams, transfer_t0, resend_pass, stream_sent,
                        stream_nobufs, pacing, success=False, failure_reason=label,
                    )
                    return False

                if all_missing:
                    seen: set = set()
                    unique_missing: List[int] = []
                    for cid in all_missing:
                        if cid not in seen:
                            seen.add(cid)
                            unique_missing.append(cid)

                    # Record this pass (chunks_lost = missing going into next pass)
                    _prev_pass_idx = resend_pass  # 0 = initial, N = resend N
                    _prev_chunks_sent = (total_chunks if resend_pass == 0
                                         else len(unique_missing))
                    _prev_pass_dur = (initial_pass_elapsed if resend_pass == 0
                                      else 0.0)  # resend durations not tracked separately
                    pass_records.append({
                        "pass_index":        _prev_pass_idx,
                        "chunks_sent":       _prev_chunks_sent,
                        "chunks_lost":       len(unique_missing),
                        "pass_duration_sec": _prev_pass_dur,
                    })
                    # Inform receiver of this pass's ramp state (diagnostic)
                    ctrl.send(
                        build_packet(
                            PacketType.LOSS_REPORT, session_id, 0,
                            build_loss_report_payload(
                                pass_index        = _prev_pass_idx,
                                chunks_sent       = _prev_chunks_sent,
                                chunks_lost       = len(unique_missing),
                                current_mbps      = pacing.target_mbps,
                                tier              = tier,
                                pass_duration_sec = _prev_pass_dur,
                            ),
                        ),
                        dest_ctrl,
                    )

                    resend_pass         += 1
                    resend_pass_live[0]  = resend_pass
                    empty_windows        = 0
                    logger.info(
                        "Consolidated RESEND #%d: %d unique IDs  rate=%s",
                        resend_pass, len(unique_missing), pacing.tier_name,
                    )
                    pacing.set_resend_mode(True, base_rate_mbs=finish_rate_mbs)
                    mgr.enqueue_pass(unique_missing, f"Resend #{resend_pass}")
                    pacing.set_resend_mode(False)
                    overall_deadline = time.monotonic() + recv_timeout

                elif got_finish_ack:
                    pass

                else:
                    empty_windows += 1
                    logger.debug("FINISH: no response (silent %d/%d)", empty_windows, max_retries)
                    if empty_windows >= max_retries:
                        logger.error(
                            "Transfer failed: %d silent FINISH windows — receiver unreachable?",
                            empty_windows,
                        )
                        break

            mgr_stats     = mgr.stop()
            stream_sent   = [s.sent   for s in mgr_stats]
            stream_nobufs = [s.nobufs for s in mgr_stats]
            stop_feedback.set()
            feedback_thread.join(timeout=2.0)
            total_nobufs = sum(stream_nobufs)
            if total_nobufs:
                logger.info("Total WSAENOBUFS: %d", total_nobufs)
            logger.info(
                "Stream workers stopped.  sent=%s  nobufs=%s  final_rate=%s",
                stream_sent, stream_nobufs, pacing.tier_name,
            )
            logger.error(
                "Transfer failed: no COMPLETE within %.0f s (%d resend passes  rate=%s)",
                recv_timeout, resend_pass, pacing.tier_name,
            )
            total_elapsed = time.monotonic() - transfer_t0
            net_total     = total_elapsed + sha_elapsed
            net_mbps      = (file_size / net_total / 1_048_576
                             if net_total > 0 else 0.0)
            transfer_id = peer_db.write_result(
                receiver_mac_key, "send",
                profile.start_mbps, peak_mbps[0],
                pacing.stable_rate_mbps,
                file_sha256.hex(), total_elapsed, success=0,
                avg_mbps=net_mbps, max_mbps=peak_mbps[0], tier=tier,
            )
            peer_db.write_loss_passes(transfer_id, pass_records)
            self._write_metrics(
                session_id, filepath, file_size, total_chunks, chunk_size,
                num_streams, transfer_t0, resend_pass, stream_sent,
                stream_nobufs, pacing, success=False, failure_reason="timeout",
            )
            return False

        finally:
            # Guarantee workers are stopped even on unexpected exception
            try:
                mgr.stop()
            except Exception:
                pass

    # ── Metrics writer ────────────────────────────────────────────────────────

    # ── Transfer summary ──────────────────────────────────────────────────────

    @staticmethod
    def _print_summary(
        filename: str,
        success: bool,
        fail_reason: str,
        sha_enabled: bool,
        sha_elapsed: float,
        sha_speed: float,
        loss_events: int,
        actual_mbps: float,
        net_mbps: float,
        direction: str,          # "send" or "receive"
    ) -> None:
        bar   = "=" * 82
        label = "successful" if success else f"failed — {fail_reason}"
        verb  = "send" if direction == "send" else "receive"

        if sha_enabled and sha_elapsed > 0:
            sha_status = (f"enabled — {sha_elapsed:.2f}s at "
                          f"{sha_speed:.1f} MB/s")
        else:
            sha_status = "disabled"

        lines = [
            bar,
            f"  Transfer of '{filename}' {label}",
            f"  Sender SHA-256 {sha_status}",
            f"  There were {loss_events} lost chunks in the initial pass",
            f"  Actual {verb} speed:  {actual_mbps:.1f} MB/s  "
            f"(initial pass only)",
            f"  Net {verb} speed:     {net_mbps:.1f} MB/s  "
            f"(SHA + transfer + resends)",
            bar,
        ]
        for line in lines:
            logger.info(line)

    def _write_metrics(
        self, session_id, filepath, file_size, total_chunks, chunk_size,
        num_streams, transfer_t0, resend_passes, stream_sent, stream_nobufs,
        pacing, success, failure_reason="",
    ) -> None:
        if not self._cfg.metrics_enabled:
            return
        duration_s = time.monotonic() - transfer_t0
        throughput = (file_size / duration_s / 1_048_576) if duration_s > 0 else 0.0
        metrics = {
            "session_id": session_id.hex(),
            "filename": os.path.basename(filepath),
            "file_size": file_size,
            "total_chunks": total_chunks,
            "chunk_size": chunk_size,
            "num_streams": num_streams,
            "duration_s": round(duration_s, 3),
            "throughput_mbps": round(throughput, 2),
            "success": success,
            "failure_reason": failure_reason,
            "resend_passes": resend_passes,
            "stream_sent": stream_sent,
            "stream_nobufs": stream_nobufs,
            "total_nobufs": sum(stream_nobufs),
            "final_rate_mbps": round(pacing.target_mbps, 2),
            "stable_rate_mbps": round(pacing.stable_rate_mbps, 2),
            "pacing_windows": pacing.get_metrics_snapshot(),
        }
        try:
            with open(self._cfg.metrics_file, "w", encoding="utf-8") as fh:
                json.dump(metrics, fh, indent=2)
            logger.info("Metrics written → %s", self._cfg.metrics_file)
        except OSError as exc:
            logger.warning("Failed to write metrics: %s", exc)
