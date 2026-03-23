"""
transport.py — UDP socket transport layer.

Wraps a single UDP socket with:
  • Windows SIO_UDP_CONNRESET suppression (prevents WinError 10054 on UDP)
  • Configurable SO_RCVBUF / SO_SNDBUF for high-throughput workloads
  • Timeout-aware recv() that returns None on timeout (no exception leakage)
  • Clean close semantics (idempotent)
  • Port 0 binding for ephemeral sender sockets

Phase 2 extension points:
  • Multi-stream: instantiate one UDPTransport per (port, stream_id) pair
  • DSCP/QoS: add setsockopt(IPPROTO_IP, IP_TOS, value) here
"""

import logging
import socket
import sys
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

UDP_MAX_PAYLOAD = 65_507

# Windows IOCTL: tells the kernel to silently discard ICMP port-unreachable
# replies instead of surfacing them as ConnectionResetError / WinError 10054
# on the next recvfrom() call.  This is the correct, permanent fix.
_SIO_UDP_CONNRESET = 0x9800000C


class UDPTransport:
    """
    A thin, thread-compatible UDP socket wrapper.

    Thread safety:
      send() and recv() may be called from different threads concurrently.
    """

    def __init__(
        self,
        bind_addr: Tuple[str, int] = ("", 0),
        buffer_size: int = 4_194_304,
    ) -> None:
        self._closed = False
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # ── Windows: suppress ICMP port-unreachable → WinError 10054 ─────────
        if sys.platform == "win32":
            try:
                self._sock.ioctl(_SIO_UDP_CONNRESET, False)
                logger.debug("SIO_UDP_CONNRESET suppressed")
            except (OSError, AttributeError, ValueError) as exc:
                logger.debug("SIO_UDP_CONNRESET ioctl unavailable: %s", exc)

        # ── Socket buffer sizing ───────────────────────────────────────────────
        # Phase 2.1: we request up to 64 MB per socket.  The OS may cap this
        # (Linux: net.core.rmem_max / net.core.wmem_max; Windows: ~8 MB without
        # elevated privileges or registry tweaks).  We read back the applied
        # value so the operator knows exactly what the kernel granted.
        try:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buffer_size)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, buffer_size)
            actual_rcv = self._sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            actual_snd = self._sock.getsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF)
            # Linux doubles the value internally; normalise for display.
            self._rcvbuf_bytes = actual_rcv // 2 if sys.platform != "win32" else actual_rcv
            self._sndbuf_bytes = actual_snd // 2 if sys.platform != "win32" else actual_snd
            if self._rcvbuf_bytes < buffer_size:
                logger.warning(
                    "SO_RCVBUF capped by OS: requested %d MB, got %d MB  "
                    "(Linux: sudo sysctl -w net.core.rmem_max=%d; "
                    "Windows: run as admin or set HKLM registry)",
                    buffer_size // 1_048_576,
                    self._rcvbuf_bytes // 1_048_576,
                    buffer_size,
                )
            if self._sndbuf_bytes < buffer_size:
                logger.warning(
                    "SO_SNDBUF capped by OS: requested %d MB, got %d MB",
                    buffer_size // 1_048_576,
                    self._sndbuf_bytes // 1_048_576,
                )
        except OSError as exc:
            logger.warning("Could not set socket buffer size to %d MB: %s",
                           buffer_size // 1_048_576, exc)
            self._rcvbuf_bytes = 0
            self._sndbuf_bytes = 0

        self._sock.bind(bind_addr)
        self._bound_addr: Tuple[str, int] = self._sock.getsockname()
        logger.debug("UDPTransport bound to %s:%d", *self._bound_addr)

    @property
    def bound_addr(self) -> Tuple[str, int]:
        return self._bound_addr

    @property
    def bound_port(self) -> int:
        return self._bound_addr[1]

    @property
    def rcvbuf_mb(self) -> int:
        """Actual SO_RCVBUF granted by the OS in MB (0 if unknown)."""
        return self._rcvbuf_bytes // 1_048_576

    @property
    def sndbuf_mb(self) -> int:
        """Actual SO_SNDBUF granted by the OS in MB (0 if unknown)."""
        return self._sndbuf_bytes // 1_048_576

    def send(self, data: bytes, addr: Tuple[str, int]) -> int:
        """
        Send *data* to *addr*.  Raises immediately on any OSError.

        WinError 10055 (WSAENOBUFS) handling
        ─────────────────────────────────────
        WSAENOBUFS is NOT retried here.  The caller (sender.py stream_worker)
        tracks consecutive failures and drives the AdaptivePacingController to
        step down through the tier ladder before retrying the same chunk.
        Retrying blindly inside transport.py would mask the loss count and
        defeat the adaptive rate logic.
        """
        if self._closed:
            raise OSError("Transport is closed")
        try:
            return self._sock.sendto(data, addr)
        except OSError as exc:
            logger.debug("send() OSError to %s:%d — %s", addr[0], addr[1], exc)
            raise

    def recv(
        self,
        timeout: float = 1.0,
        buf_size: int = UDP_MAX_PAYLOAD,
    ) -> Optional[Tuple[bytes, Tuple[str, int]]]:
        """
        Block up to *timeout* seconds for an incoming datagram.
        Returns (data, addr) or None on timeout/suppressed error.
        """
        if self._closed:
            raise OSError("Transport is closed")
        self._sock.settimeout(timeout)
        try:
            data, addr = self._sock.recvfrom(buf_size)
            return data, addr
        except socket.timeout:
            return None
        except ConnectionResetError:
            # Belt-and-suspenders: catches WinError 10054 if ioctl was unavailable
            logger.debug("recv() ICMP port-unreachable (WinError 10054) — ignored")
            return None
        except OSError as exc:
            if self._closed:
                return None
            # Final fallback: some Windows builds route 10054 as a plain OSError
            if getattr(exc, "winerror", None) == 10054:
                logger.debug("recv() winerror=10054 — ignored")
                return None
            logger.error("recv() error — %s", exc)
            raise

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            try:
                self._sock.close()
            except OSError:
                pass
            logger.debug("UDPTransport closed (%s:%d)", *self._bound_addr)

    def __enter__(self) -> "UDPTransport":
        return self

    def __exit__(self, *_) -> None:
        self.close()