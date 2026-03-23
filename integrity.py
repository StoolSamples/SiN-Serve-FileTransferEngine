"""
integrity.py — Integrity engine for FastTransfer.

Per-chunk integrity (in-flight corruption detection):
    xxHash XXH3-64 via the xxhash library (pip install xxhash).
    ~30-50 GB/s vs ~600 MB/s for SHA-256.  Correct choice for UDP chunk
    verification where the goal is bit-flip / corruption detection, not
    cryptographic security.

    Wire format: the DATA packet checksum field is 32 bytes (sized for SHA-256).
    XXH3-64 produces 8 bytes.  The remaining 24 bytes are zero-padded on send
    and only the first CHUNK_DIGEST_SIZE bytes are compared on receive.
    The padding is intentional — a future revision can swap the algorithm
    without a protocol version bump once testing is complete.

Whole-file integrity (end-to-end transfer verification):
    SHA-256 is retained for the file-level check (FINISH / COMPLETE handshake).
    Computed once per transfer on a cold file; the stronger guarantee is worth
    keeping here.

Public API:
    CHUNK_DIGEST_SIZE               int   = 8  (bytes produced by XXH3-64)
    CHUNK_WIRE_SIZE                 int   = 32 (bytes on the wire, padded)

    compute_chunk_hash(data)        -> 32-byte wire value (8-byte digest + 24 zero pad)
    verify_chunk_hash(data, wire)   -> bool  (compares first CHUNK_DIGEST_SIZE bytes)

    compute_file_sha256(path)       -> 32-byte SHA-256 digest
    format_hex(digest)              -> lowercase hex string
"""

import hashlib
import logging
import os
import time

import xxhash

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

CHUNK_DIGEST_SIZE: int = 8    # bytes produced by XXH3-64
CHUNK_WIRE_SIZE:   int = 32   # bytes in the DATA packet checksum field
_ZERO_PAD          = bytes(CHUNK_WIRE_SIZE - CHUNK_DIGEST_SIZE)  # 24 zero bytes

# File hashing block size: 32 MiB minimises syscall overhead.
# 8 GiB file -> ~256 read() calls vs ~130,000 at 64 KiB.
_FILE_READ_BLOCK = 32 * 1024 * 1024


# ── Per-chunk integrity (XXH3-64) ─────────────────────────────────────────────

def compute_chunk_hash(data: bytes) -> bytes:
    """
    Return 32-byte wire value for the DATA packet checksum field.

    Layout: xxh3_64(data)[8 bytes] + 0x00 * 24

    The zero-pad keeps the wire format compatible with the existing 32s
    protocol field.  verify_chunk_hash() reads only the first 8 bytes.
    """
    return xxhash.xxh3_64(data).digest() + _ZERO_PAD


def verify_chunk_hash(data: bytes, wire_checksum: bytes) -> bool:
    """
    Return True iff xxh3_64(data) matches the first CHUNK_DIGEST_SIZE bytes
    of wire_checksum.

    Safe whether wire_checksum is 8 or 32 bytes.
    """
    actual = xxhash.xxh3_64(data).digest()
    return actual == wire_checksum[:CHUNK_DIGEST_SIZE]


# ── Whole-file integrity (SHA-256) ────────────────────────────────────────────

def compute_file_sha256(filepath: str) -> bytes:
    """
    Stream-hash an entire file and return its 32-byte SHA-256 digest.

    Used for:
      - Pre-transfer hash on the sender (sent in FINISH packet)
      - Post-receive whole-file verification on the receiver

    Reads in _FILE_READ_BLOCK (32 MiB) chunks for minimal syscall overhead.
    Logs elapsed time and effective read throughput.
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    file_size = os.path.getsize(filepath)
    h         = hashlib.sha256()
    t0        = time.monotonic()

    with open(filepath, "rb") as fh:
        while True:
            block = fh.read(_FILE_READ_BLOCK)
            if not block:
                break
            h.update(block)

    elapsed = time.monotonic() - t0
    mbps    = (file_size / elapsed / 1_048_576) if elapsed > 0 else 0.0
    logger.info(
        "SHA-256 complete: %.1f MB hashed in %.3f s = %.1f MB/s  "
        "(block_size=%d MB, file=%r)",
        file_size / 1_048_576, elapsed, mbps,
        _FILE_READ_BLOCK // 1_048_576,
        os.path.basename(filepath),
    )
    return h.digest()


# ── Helpers ───────────────────────────────────────────────────────────────────

def format_hex(digest: bytes) -> str:
    """Return lowercase hex string for log messages."""
    return digest.hex()


# ── Backward-compat shims ─────────────────────────────────────────────────────
# Allows any callers still using the old SHA-256 names to keep working.
# Remove after sender.py / receiver.py call sites are fully migrated.

def compute_sha256(data: bytes) -> bytes:
    """Deprecated shim -> compute_chunk_hash(). Returns 32-byte padded wire value."""
    return compute_chunk_hash(data)


def verify_sha256(data: bytes, expected: bytes) -> bool:
    """Deprecated shim -> verify_chunk_hash()."""
    return verify_chunk_hash(data, expected)
