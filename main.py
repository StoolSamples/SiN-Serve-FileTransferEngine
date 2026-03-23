"""
main.py — FastTransfer CLI entry point.

Usage:
    # Receive a file (start receiver first)
    python main.py recv --port 9000 --output /tmp/received

    # Send a file
    python main.py send /path/to/file.bin --host 127.0.0.1 --port 9000

    # Self-test: loopback transfer in two threads (no real network needed)
    python main.py test --file /path/to/testfile --size 10

    # Generate a test file of <size> MB
    python main.py genfile --output /tmp/test.bin --size 50
"""

import argparse
import logging
import os
import sys
import tempfile
import threading
import time

logger = logging.getLogger("fasttransfer.main")


# ─── command handlers ─────────────────────────────────────────────────────────

def _make_peer_reset_hook():
    """
    Returns a callable that FileSender invokes after identifying a peer.
    Receives a peer dict (mac_key, tier, send_count, last_seen) and returns
    True when the caller confirmed a stats reset, False otherwise.
    """
    import peer_db

    def hook(peer: dict) -> bool:
        mac_key   = peer["mac_key"]
        confirmed = _timed_yes(
            f"User {mac_key} found  "
            f"[tier {peer['tier']}  sends={peer['send_count']}  "
            f"last seen {peer['last_seen']}]\n"
            f'Press "Y" to reset stats.',
        )
        if confirmed:
            reset_ok = peer_db.reset_peer_stats(mac_key)
            if reset_ok:
                print(f"✓ Stats reset — {mac_key} will use tier-0 cold-start.")
            else:
                print(f"  No send record found for {mac_key} — already at tier 0.")
        else:
            print("Reset skipped — proceeding with existing tier profile.")
        return confirmed

    return hook


def cmd_send(args) -> int:
    from transfer_controller import TransferController
    ctrl = TransferController(config_path=args.config)
    ctrl.set_peer_reset_hook(_make_peer_reset_hook())
    ok = ctrl.send(filepath=args.file, host=args.host, port=args.port)
    return 0 if ok else 1


def cmd_recv(args) -> int:
    from transfer_controller import TransferController
    ctrl = TransferController(config_path=args.config)
    os.makedirs(args.output, exist_ok=True)
    try:
        path = ctrl.receive(output_dir=args.output, port=args.port)
        print(f"\n✓ Received: {path}")
        return 0
    except RuntimeError as exc:
        print(f"\n✗ Receive failed: {exc}", file=sys.stderr)
        return 1


def cmd_genfile(args) -> int:
    """Generate a deterministic binary test file of the requested size."""
    import hashlib

    size_bytes = args.size * 1024 * 1024
    out_path   = args.output
    block_size = 1 << 20  # 1 MiB

    print(f"Generating {args.size} MiB test file → {out_path} …")
    sha = hashlib.sha256()
    written = 0
    with open(out_path, "wb") as fh:
        counter = 0
        while written < size_bytes:
            # Deterministic but non-trivial bytes (not all zeros)
            chunk = (str(counter).encode() * (block_size // 4 + 1))[:block_size]
            remaining = size_bytes - written
            to_write = chunk[:remaining]
            fh.write(to_write)
            sha.update(to_write)
            written += len(to_write)
            counter += 1

    actual_size = os.path.getsize(out_path)
    print(f"✓ Generated {actual_size / 1_048_576:.1f} MiB  SHA-256={sha.hexdigest()[:16]}…")
    return 0


def cmd_test(args) -> int:
    """
    Loopback self-test: receiver in a background thread, sender in foreground.
    Verifies end-to-end correctness without real network hardware.
    """
    from transfer_controller import TransferController

    # --- Create test file ---
    size_mb     = args.size
    src_dir     = tempfile.mkdtemp(prefix="ft_send_")
    recv_dir    = tempfile.mkdtemp(prefix="ft_recv_")
    src_file    = os.path.join(src_dir, f"testfile_{size_mb}mb.bin")
    test_port   = args.port

    print(f"Self-test: {size_mb} MiB file, port {test_port}")

    # Generate test data
    print("Generating test file …")
    block = bytes(range(256)) * 4096            # 1 MiB of patterned data
    target = size_mb * 1024 * 1024
    with open(src_file, "wb") as fh:
        written = 0
        while written < target:
            chunk = block[:target - written]
            fh.write(chunk)
            written += len(chunk)
    print(f"  Source: {src_file}  ({size_mb} MiB)")

    from integrity import compute_file_sha256, format_hex
    src_sha = compute_file_sha256(src_file)
    print(f"  Source SHA-256: {format_hex(src_sha)}")

    # --- Start receiver in background thread ---
    recv_result     = {}
    recv_error      = {}
    recv_ready      = threading.Event()

    def run_receiver():
        ctrl = TransferController(config_path=args.config)
        # Signal ready just before entering blocking recv
        recv_ready.set()
        try:
            path = ctrl.receive(output_dir=recv_dir, port=test_port)
            recv_result["path"] = path
        except Exception as exc:
            recv_error["exc"] = exc

    t = threading.Thread(target=run_receiver, daemon=True)
    t.start()

    # Wait for receiver to be ready
    recv_ready.wait(timeout=5.0)
    time.sleep(0.3)   # small grace period for socket bind

    # --- Send ---
    ctrl = TransferController(config_path=args.config)
    from stream_manager import ScalingDecision
    ctrl.set_scaling_hook(lambda mgr: ScalingDecision(), probe_interval_s=2.0)
    ok   = ctrl.send(filepath=src_file, host="127.0.0.1", port=test_port)

    t.join(timeout=30.0)

    if not ok:
        print("✗ Sender reported failure.", file=sys.stderr)
        return 1

    if "exc" in recv_error:
        print(f"✗ Receiver error: {recv_error['exc']}", file=sys.stderr)
        return 1

    if "path" not in recv_result:
        print("✗ Receiver did not return a path (timed out?).", file=sys.stderr)
        return 1

    recv_file = recv_result["path"]
    recv_sha  = compute_file_sha256(recv_file)
    print(f"\n  Received: {recv_file}")
    print(f"  Recv SHA-256: {format_hex(recv_sha)}")

    if src_sha == recv_sha:
        print("\n✓ SELF-TEST PASSED — SHA-256 matches perfectly.")
        return 0
    else:
        print("\n✗ SELF-TEST FAILED — SHA-256 MISMATCH!", file=sys.stderr)
        return 1


def _timed_yes(prompt: str, timeout: float = 2.5) -> bool:
    """
    Print *prompt*, then wait up to *timeout* seconds for the user to type 'Y'.
    Returns True only if 'Y' (case-insensitive) is entered before the timeout.
    Defaults to False (no) on timeout or any other input.
    """
    print(prompt, flush=True)

    answered = threading.Event()
    result   = [False]

    def _reader():
        try:
            val = input()
            result[0] = val.strip().upper() == "Y"
        except (EOFError, OSError):
            pass
        finally:
            answered.set()

    t = threading.Thread(target=_reader, daemon=True)
    t.start()

    remaining = timeout
    interval  = 0.1
    while remaining > 0 and not answered.is_set():
        answered.wait(timeout=min(interval, remaining))
        remaining -= interval
        if not answered.is_set() and remaining > 0:
            secs_left = int(remaining) + 1
            print(f"\r  Auto-cancelling in {secs_left}s … (press Y to confirm)   ",
                  end="", flush=True)

    if not answered.is_set():
        print("\r  Timed out — no action taken.                              ")

    return result[0]


def cmd_reset(args) -> int:
    """
    Locate a peer by user ID (mac_key prefix or full key), confirm via timed
    prompt, then wipe their send-direction speed record so the next session
    starts at tier 0.
    """
    import peer_db

    peer_db.init(args.db)

    try:
        peer = peer_db.find_peer(args.user_id)
    except ValueError as exc:
        print(f"✗ {exc}", file=sys.stderr)
        return 1

    if peer is None:
        print(f"✗ User '{args.user_id}' not found in the peer database.")
        return 1

    mac_key = peer["mac_key"]
    confirmed = _timed_yes(
        f"User {mac_key} found  "
        f"[tier {peer['tier']}  sends={peer['send_count']}  "
        f"last seen {peer['last_seen']}]\n"
        f'Press "Y" to reset stats.',
    )

    if not confirmed:
        print("Reset cancelled.")
        return 0

    reset_ok = peer_db.reset_peer_stats(mac_key)
    if reset_ok:
        print(f"✓ Stats reset for {mac_key}. Next send will use tier-0 cold-start profile.")
    else:
        print(f"  No send record found for {mac_key} — already at tier 0.")
    return 0


# ─── argument parser ──────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fasttransfer",
        description="FastTransfer — high-performance UDP file transfer (Phase 1)",
    )
    p.add_argument("--config", default="config.json", metavar="PATH",
                   help="Path to config.json (default: config.json)")

    sub = p.add_subparsers(dest="command", required=True)

    # send
    sp = sub.add_parser("send", help="Send a file to a remote receiver")
    sp.add_argument("file",            help="Path to the file to send")
    sp.add_argument("--host", "-H",    required=True, help="Receiver host/IP")
    sp.add_argument("--port", "-p",    type=int, default=9000, help="Receiver UDP port")

    # recv
    rp = sub.add_parser("recv", help="Receive a file from a remote sender")
    rp.add_argument("--port",   "-p", type=int, default=9000, help="UDP port to listen on")
    rp.add_argument("--output", "-o", default=".", help="Output directory (default: .)")

    # genfile
    gp = sub.add_parser("genfile", help="Generate a test file of a given size")
    gp.add_argument("--output", "-o", required=True, help="Output file path")
    gp.add_argument("--size",   "-s", type=int, default=10,
                    help="File size in MiB (default: 10)")

    # test
    tp = sub.add_parser("test", help="Run a loopback self-test")
    tp.add_argument("--size", "-s", type=int, default=10,
                    help="Test file size in MiB (default: 10)")
    tp.add_argument("--port", "-p", type=int, default=19000,
                    help="UDP port for loopback test (default: 19000)")

    # reset
    rsp = sub.add_parser("reset", help="Reset a peer's tier stats back to tier 0")
    rsp.add_argument("user_id", metavar="USER_ID",
                     help="Peer mac_key or unambiguous prefix")
    rsp.add_argument("--db", default="peer_db.sqlite", metavar="PATH",
                     help="Path to peer database (default: peer_db.sqlite)")

    return p


# ─── entry point ──────────────────────────────────────────────────────────────

def main() -> int:
    parser = build_parser()
    args   = parser.parse_args()

    dispatch = {
        "send":    cmd_send,
        "recv":    cmd_recv,
        "genfile": cmd_genfile,
        "test":    cmd_test,
        "reset":   cmd_reset,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        return 1

    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
