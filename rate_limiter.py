
import threading
import time
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class TokenBucket:

    def __init__(self, limit_bps: float = 0, burst_size: Optional[int] = None) -> None:
        self._limit_bps = limit_bps
        self._enabled = limit_bps > 0

        if self._enabled:
            self._burst = burst_size if burst_size is not None else int(limit_bps * 2)
            self._tokens: float = float(self._burst)
            self._last_refill: float = time.monotonic()
            self._lock = threading.Lock()
            logger.debug(
                "TokenBucket: %.2f MB/s limit, %d byte burst",
                limit_bps / 1_048_576,
                self._burst,
            )

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    def acquire(self, nbytes: int) -> None:
        """
        Block until nbytes tokens are available.

        Thread-safety: lock is RELEASED before sleeping to avoid holding it
        across the sleep, then re-acquired on retry.  All token-bucket state
        is mutated only while the lock is held.
        """
        if not self._enabled:
            return

        while True:
            with self._lock:
                # ── Refill based on elapsed time ──────────────────────────
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._last_refill = now
                self._tokens = min(
                    float(self._burst),
                    self._tokens + elapsed * self._limit_bps,
                )

                if self._tokens >= nbytes:
                    # Sufficient tokens — consume and return immediately
                    self._tokens -= nbytes
                    return

                # Not enough tokens: compute required sleep, then drop lock
                # before sleeping so other threads are not blocked.
                deficit = nbytes - self._tokens
                sleep_s = deficit / self._limit_bps
                # Lock releases at end of `with` block (before sleep)

            # ── Lock is released here ─────────────────────────────────────
            time.sleep(sleep_s)
            # Retry: re-acquire lock and recheck (another thread may have
            # consumed tokens in the interim).


class RateLimiter:

    def __init__(
        self,
        send_limit_mbps: float = 0,
        recv_limit_mbps: float = 0,
    ) -> None:
        send_bps = send_limit_mbps * 1_048_576
        recv_bps = recv_limit_mbps * 1_048_576
        self._send = TokenBucket(limit_bps=send_bps)
        self._recv = TokenBucket(limit_bps=recv_bps)

        if self._send.is_enabled:
            logger.info("Rate limiter: send capped at %.1f MB/s", send_limit_mbps)
        if self._recv.is_enabled:
            logger.info("Rate limiter: recv capped at %.1f MB/s", recv_limit_mbps)

    def acquire_send(self, nbytes: int) -> None:
        self._send.acquire(nbytes)

    def acquire_recv(self, nbytes: int) -> None:
        self._recv.acquire(nbytes)

    @property
    def send_enabled(self) -> bool:
        return self._send.is_enabled

    @property
    def recv_enabled(self) -> bool:
        return self._recv.is_enabled

