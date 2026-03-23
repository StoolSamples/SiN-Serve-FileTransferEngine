"""
peer_db.py — Persistent per-peer speed database.

Stores per-peer transfer history, per-pass loss detail, and stable-speed
records so that each new session can start at the last known good rate
instead of the cold-start default.

Thread safety
─────────────
All writes are serialised through a module-level threading.Lock.
The connection is opened in WAL mode so concurrent readers (including
other processes on the same machine) never block writers.

Startup
───────
Call init() exactly once at process startup, before any threads are
created.  get_local_key() is called by init() so the identity row is
written before any concurrent DB access begins.

Identity key
────────────
The local node's stable 32-char hex key is derived from the hardware MAC
address via SHA-256.  If uuid.getnode() returns a value with the multicast
bit (0x010000000000) set — meaning Python could not find a real NIC and
generated a random address — we fall back to a random UUID that is
persisted across restarts instead.
"""

import hashlib
import logging
import sqlite3
import threading
import time
import uuid
from typing import List, Optional

logger = logging.getLogger(__name__)

# ── Module-level state ────────────────────────────────────────────────────────

_lock:      threading.Lock              = threading.Lock()
_conn:      Optional[sqlite3.Connection] = None
_local_key: Optional[str]              = None   # cached after init()


# ── Public API ────────────────────────────────────────────────────────────────

def init(db_path: str = "peer_db.sqlite") -> None:
    """
    Open (or create) the database, ensure the schema exists, and eagerly
    resolve the local identity key.

    Must be called once at process startup before any other function in
    this module, and before any threads are started.
    """
    global _conn, _local_key
    with _lock:
        _conn = _open_connection(db_path)
        _create_schema(_conn)
        _local_key = _get_or_create_key(_conn)
    logger.info("peer_db ready  key=%s  path=%s", _local_key, db_path)


def get_local_key() -> str:
    """
    Return this node's stable 32-char hex identity key.
    init() must have been called first.
    """
    if _local_key is None:
        raise RuntimeError("peer_db.init() has not been called")
    return _local_key


def upsert_peer(mac_key: str) -> None:
    """
    Record (or update) a peer's first/last-seen timestamps.
    No-op when mac_key is empty (old sender that did not send a key).
    """
    if not mac_key:
        return
    now = _now()
    with _lock:
        existing = _conn.execute(
            "SELECT first_seen FROM peers WHERE mac_key=?", (mac_key,)
        ).fetchone()
        if existing:
            _conn.execute(
                "UPDATE peers SET last_seen=? WHERE mac_key=?", (now, mac_key)
            )
        else:
            _conn.execute(
                "INSERT INTO peers (mac_key, first_seen, last_seen) VALUES (?,?,?)",
                (mac_key, now, now),
            )
        _conn.commit()


def get_stable_mbps(mac_key: str, direction: str) -> Optional[float]:
    """
    Return the recorded stable speed for (peer, direction), or None if no
    record exists.  direction is 'send' or 'recv'.
    """
    if not mac_key:
        return None
    row = _conn.execute(
        "SELECT stable_mbps FROM peer_speeds WHERE mac_key=? AND direction=?",
        (mac_key, direction),
    ).fetchone()
    return float(row[0]) if row else None


def get_best_stable_mbps(mac_key: str) -> Optional[float]:
    """
    Return the best available stable speed for a peer, regardless of
    transfer direction.

    Checks 'send' first.  If no send record exists, falls back to 'recv'.
    Links are approximately symmetric, so a recv record is a useful proxy
    when this node has only ever received from a peer and is now about to
    send to it (role reversal).  Returns None only when no record exists
    in either direction.
    """
    if not mac_key:
        return None
    return get_stable_mbps(mac_key, "send") or get_stable_mbps(mac_key, "recv")


def get_avg_stable_mbps(mac_key: str, direction: str) -> Optional[float]:
    """
    Return the running-average stable speed for (peer, direction), or None
    if no record exists.  Used by tier 1–3 profile selection to start at a
    more conservative estimate than the peak.
    """
    if not mac_key:
        return None
    row = _conn.execute(
        "SELECT avg_stable_mbps FROM peer_speeds WHERE mac_key=? AND direction=?",
        (mac_key, direction),
    ).fetchone()
    if row is None:
        return None
    val = row[0]
    return float(val) if val and val > 0.0 else None


def get_peer_send_count(mac_key: str) -> int:
    """
    Return the number of successful sends recorded for this peer.
    Returns 0 if the peer has never been seen or only received.
    """
    if not mac_key:
        return 0
    row = _conn.execute(
        "SELECT send_count FROM peer_speeds WHERE mac_key=? AND direction='send'",
        (mac_key,),
    ).fetchone()
    return int(row[0]) if row else 0


def write_result(
    peer_key:          str,
    direction:         str,
    start_mbps:        float,
    peak_mbps:         float,
    final_stable_mbps: float,
    file_hash:         str,
    duration_sec:      float,
    success:           int,
    avg_mbps:          float = 0.0,
    max_mbps:          float = 0.0,
    tier:              int   = 0,
) -> int:
    """
    Append a row to transfer_history.  When success=1, also upsert
    peer_speeds so the next session can start at final_stable_mbps.
    When success=0, only the history row is written — peer_speeds is
    left unchanged.

    Note: for direction='recv' rows, start_mbps is always 0.0.  The
    receiver has no ramp profile, so this field is not meaningful for
    recv-direction analytics queries.  It is stored as 0.0 to keep the
    schema uniform.

    Returns the rowid of the newly inserted transfer_history row so that
    callers can associate per-pass loss records via write_loss_passes().
    """
    if not peer_key:
        return 0
    now = _now()
    with _lock:
        cur = _conn.execute(
            """
            INSERT INTO transfer_history
                (peer_key, direction, start_mbps, peak_mbps, final_stable_mbps,
                 file_hash, duration_sec, success, timestamp,
                 avg_mbps, max_mbps, tier)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (peer_key, direction, start_mbps, peak_mbps, final_stable_mbps,
             file_hash, duration_sec, success, now,
             avg_mbps, max_mbps, tier),
        )
        transfer_id = cur.lastrowid
        if success == 1:
            _conn.execute(
                """
                INSERT INTO peer_speeds
                    (mac_key, direction, stable_mbps, updated_at,
                     avg_stable_mbps, max_mbps, peak_mbps, avg_mbps, send_count)
                VALUES (?,?,?,?,?,?,?,?,1)
                ON CONFLICT(mac_key, direction) DO UPDATE SET
                    stable_mbps     = excluded.stable_mbps,
                    updated_at      = excluded.updated_at,
                    max_mbps        = MAX(peer_speeds.max_mbps, excluded.max_mbps),
                    peak_mbps       = MAX(peer_speeds.peak_mbps, excluded.peak_mbps),
                    send_count      = peer_speeds.send_count + 1,
                    avg_stable_mbps = (
                        peer_speeds.avg_stable_mbps * peer_speeds.send_count
                        + excluded.stable_mbps
                    ) / (peer_speeds.send_count + 1),
                    avg_mbps        = (
                        peer_speeds.avg_mbps * peer_speeds.send_count
                        + excluded.avg_mbps
                    ) / (peer_speeds.send_count + 1)
                """,
                (peer_key, direction, final_stable_mbps, now,
                 final_stable_mbps, max_mbps, peak_mbps, avg_mbps),
            )
        _conn.commit()
    logger.info(
        "peer_db write_result  peer=%s…  dir=%s  start=%.1f  peak=%.1f  "
        "stable=%.1f  avg=%.1f  max=%.1f  tier=%d  success=%d  id=%d",
        peer_key[:8], direction, start_mbps, peak_mbps, final_stable_mbps,
        avg_mbps, max_mbps, tier, success, transfer_id,
    )
    return transfer_id


def list_peers() -> List[dict]:
    """
    Return all known peers with their send stats.

    Each entry is a dict with keys:
        mac_key      str   — 32-char hex identity
        first_seen   str   — ISO timestamp
        last_seen    str   — ISO timestamp
        send_count   int   — successful sends recorded
        tier         int   — 0/1/2/3 derived from send_count
    """
    with _lock:
        rows = _conn.execute(
            """
            SELECT p.mac_key, p.first_seen, p.last_seen,
                   COALESCE(ps.send_count, 0) AS send_count
            FROM   peers p
            LEFT JOIN peer_speeds ps
                   ON ps.mac_key = p.mac_key AND ps.direction = 'send'
            ORDER  BY p.last_seen DESC
            """
        ).fetchall()

    result = []
    for mac_key, first_seen, last_seen, send_count in rows:
        if send_count == 0:
            tier = 0
        elif send_count < 10:
            tier = 1
        elif send_count < 20:
            tier = 2
        else:
            tier = 3
        result.append(
            dict(mac_key=mac_key, first_seen=first_seen,
                 last_seen=last_seen, send_count=send_count, tier=tier)
        )
    return result


def find_peer(user_id: str) -> Optional[dict]:
    """
    Find a peer by exact mac_key or unambiguous prefix.
    Returns a dict (same shape as list_peers entries) or None when not found.
    Raises ValueError when user_id matches more than one peer.
    """
    peers = list_peers()
    matches = [p for p in peers if p["mac_key"].startswith(user_id)]
    if not matches:
        return None
    if len(matches) > 1:
        raise ValueError(
            f"{len(matches)} peers match prefix '{user_id}'. "
            "Provide a longer prefix or the full key."
        )
    return matches[0]


def reset_peer_stats(mac_key: str) -> bool:
    """
    Delete the send-direction speed record for *mac_key*, resetting the peer
    to tier 0.  Transfer history is intentionally preserved for auditability.

    Returns True when a row was deleted, False when the peer had no send record.
    """
    with _lock:
        cur = _conn.execute(
            "DELETE FROM peer_speeds WHERE mac_key=? AND direction='send'",
            (mac_key,),
        )
        _conn.commit()
    deleted = cur.rowcount > 0
    if deleted:
        logger.info("peer_db reset_peer_stats  peer=%s…  send record removed", mac_key[:8])
    else:
        logger.debug("peer_db reset_peer_stats  peer=%s…  no send record found", mac_key[:8])
    return deleted


def write_loss_passes(transfer_id: int, passes: list) -> None:
    """
    Insert per-pass loss records for a completed transfer.

    passes is a list of dicts with keys:
        pass_index       int
        chunks_sent      int
        chunks_lost      int
        pass_duration_sec float

    No-op when transfer_id is 0 (write_result was skipped) or passes is empty.
    """
    if not transfer_id or not passes:
        return
    with _lock:
        _conn.executemany(
            """
            INSERT INTO transfer_loss_passes
                (transfer_id, pass_index, chunks_sent, chunks_lost, pass_duration_sec)
            VALUES (?,?,?,?,?)
            """,
            [
                (transfer_id, p["pass_index"], p["chunks_sent"],
                 p["chunks_lost"], p["pass_duration_sec"])
                for p in passes
            ],
        )
        _conn.commit()
    logger.debug(
        "peer_db write_loss_passes  transfer_id=%d  passes=%d",
        transfer_id, len(passes),
    )


# ── Internals ─────────────────────────────────────────────────────────────────

def _open_connection(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def _create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS local_identity (
            id         INTEGER PRIMARY KEY CHECK (id = 1),
            mac_key    TEXT    NOT NULL,
            created_at TEXT    NOT NULL,
            fallback   INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS peers (
            mac_key    TEXT PRIMARY KEY,
            first_seen TEXT NOT NULL,
            last_seen  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS peer_speeds (
            mac_key         TEXT NOT NULL,
            direction       TEXT NOT NULL,
            stable_mbps     REAL NOT NULL,
            updated_at      TEXT NOT NULL,
            avg_stable_mbps REAL NOT NULL DEFAULT 0.0,
            max_mbps        REAL NOT NULL DEFAULT 0.0,
            peak_mbps       REAL NOT NULL DEFAULT 0.0,
            avg_mbps        REAL NOT NULL DEFAULT 0.0,
            send_count      INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY (mac_key, direction)
        );

        CREATE TABLE IF NOT EXISTS transfer_history (
            id                INTEGER PRIMARY KEY,
            peer_key          TEXT    NOT NULL,
            direction         TEXT    NOT NULL,
            start_mbps        REAL    NOT NULL,
            peak_mbps         REAL    NOT NULL,
            final_stable_mbps REAL    NOT NULL,
            file_hash         TEXT    NOT NULL,
            duration_sec      REAL    NOT NULL,
            success           INTEGER NOT NULL,
            timestamp         TEXT    NOT NULL,
            avg_mbps          REAL    NOT NULL DEFAULT 0.0,
            max_mbps          REAL    NOT NULL DEFAULT 0.0,
            tier              INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS transfer_loss_passes (
            id                INTEGER PRIMARY KEY,
            transfer_id       INTEGER NOT NULL REFERENCES transfer_history(id),
            pass_index        INTEGER NOT NULL,
            chunks_sent       INTEGER NOT NULL,
            chunks_lost       INTEGER NOT NULL,
            pass_duration_sec REAL    NOT NULL
        );
    """)
    conn.commit()

    # Migrate existing databases that pre-date the expanded schema.
    # Each ALTER is wrapped in its own try/except because sqlite3 raises
    # OperationalError when a column already exists — we cannot use
    # IF NOT EXISTS for ADD COLUMN in older SQLite versions.
    _add_column_if_missing(conn, "peer_speeds",       "avg_stable_mbps", "REAL NOT NULL DEFAULT 0.0")
    _add_column_if_missing(conn, "peer_speeds",       "max_mbps",        "REAL NOT NULL DEFAULT 0.0")
    _add_column_if_missing(conn, "peer_speeds",       "peak_mbps",       "REAL NOT NULL DEFAULT 0.0")
    _add_column_if_missing(conn, "peer_speeds",       "avg_mbps",        "REAL NOT NULL DEFAULT 0.0")
    _add_column_if_missing(conn, "peer_speeds",       "send_count",      "INTEGER NOT NULL DEFAULT 0")
    _add_column_if_missing(conn, "transfer_history",  "avg_mbps",        "REAL NOT NULL DEFAULT 0.0")
    _add_column_if_missing(conn, "transfer_history",  "max_mbps",        "REAL NOT NULL DEFAULT 0.0")
    _add_column_if_missing(conn, "transfer_history",  "tier",            "INTEGER NOT NULL DEFAULT 0")
    conn.commit()


def _add_column_if_missing(
    conn: sqlite3.Connection,
    table: str,
    column: str,
    definition: str,
) -> None:
    try:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
    except sqlite3.OperationalError:
        pass  # column already exists


def _get_or_create_key(conn: sqlite3.Connection) -> str:
    """
    Read the persisted identity key, or generate and store it on first run.
    Must be called with _lock held.
    """
    row = conn.execute("SELECT mac_key FROM local_identity WHERE id=1").fetchone()
    if row:
        return row[0]

    node        = uuid.getnode()
    is_fallback = bool(node & 0x010000000000)

    if is_fallback:
        # uuid.getnode() could not find a real NIC; use a stable random UUID.
        raw = uuid.uuid4().bytes
        logger.info(
            "peer_db: uuid.getnode() returned virtual/multicast MAC — "
            "using persisted random UUID for identity key"
        )
    else:
        raw = node.to_bytes(6, "big")

    mac_key = hashlib.sha256(raw).hexdigest()[:32]
    now     = _now()
    conn.execute(
        "INSERT INTO local_identity (id, mac_key, created_at, fallback) "
        "VALUES (1, ?, ?, ?)",
        (mac_key, now, int(is_fallback)),
    )
    conn.commit()
    logger.info(
        "peer_db: identity key created  key=%s  fallback=%s",
        mac_key, is_fallback,
    )
    return mac_key


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
