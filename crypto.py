"""
crypto.py — AES-256-GCM encryption engine.

Phase 1: disabled pass-through (encrypt/decrypt are identity functions).
Phase 2: set crypto.enabled = true in config.json and supply a 32-byte key.

Only DATA packet payloads are encrypted (header and chunk metadata are
transmitted in cleartext so the receiver can seek and track chunks without
decrypting the envelope first).

Wire format for an encrypted DATA payload (Phase 2):
  nonce(12 bytes) || ciphertext+tag(chunk_data_size + 16 bytes)

The SHA-256 checksum in every DATA packet is always computed over the
PLAINTEXT so integrity can be verified after decryption.

Dependencies (Phase 2 only):
  pip install cryptography
"""

import logging
import os
from typing import Optional, Tuple

logger = logging.getLogger(__name__)

# AES-256-GCM nonce length (NIST recommended: 12 bytes)
NONCE_LENGTH = 12

# AES-256 requires exactly a 32-byte key
KEY_LENGTH = 32


class CryptoEngine:
    """
    AES-256-GCM encryption / decryption engine.

    Phase 1 behaviour:
        is_enabled  → False
        encrypt()   → returns (b"", plaintext)  [nonce=empty, ct=original]
        decrypt()   → returns ciphertext unchanged

    Phase 2 behaviour (requires `cryptography` package):
        encrypt()   → generates 12-byte random nonce, returns (nonce, ct+tag)
        decrypt()   → decrypts and authenticates; raises ValueError on failure
    """

    def __init__(
        self,
        enabled: bool = False,
        key: Optional[bytes] = None,
    ) -> None:
        self._enabled = enabled
        self._key = key
        self._aesgcm = None

        if enabled:
            if key is None:
                raise ValueError(
                    "CryptoEngine: encryption enabled but no key supplied. "
                    "Provide a 32-byte key."
                )
            if len(key) != KEY_LENGTH:
                raise ValueError(
                    f"CryptoEngine: key must be exactly {KEY_LENGTH} bytes "
                    f"(AES-256), got {len(key)}."
                )
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                self._aesgcm = AESGCM(key)
                logger.info("CryptoEngine: AES-256-GCM enabled")
            except ImportError as exc:
                raise ImportError(
                    "The 'cryptography' package is required for encryption. "
                    "Install it with:  pip install cryptography"
                ) from exc
        else:
            logger.debug("CryptoEngine: disabled (Phase 1 pass-through)")

    # ── properties ────────────────────────────────────────────────────────────

    @property
    def is_enabled(self) -> bool:
        return self._enabled

    # ── core operations ───────────────────────────────────────────────────────

    def encrypt(
        self,
        plaintext: bytes,
        aad: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """
        Encrypt *plaintext* with AES-256-GCM.

        Args:
            plaintext: data to encrypt (chunk payload bytes)
            aad:       additional authenticated data (e.g. packet header);
                       authenticated but not encrypted.  May be None.

        Returns:
            (nonce, ciphertext_with_tag)
            Phase 1: (b"", plaintext)
        """
        if not self._enabled:
            return b"", plaintext

        nonce = os.urandom(NONCE_LENGTH)
        ct = self._aesgcm.encrypt(nonce, plaintext, aad)
        return nonce, ct

    def decrypt(
        self,
        nonce: bytes,
        ciphertext: bytes,
        aad: Optional[bytes] = None,
    ) -> bytes:
        """
        Decrypt and authenticate *ciphertext*.

        Args:
            nonce:      12-byte nonce from the DATA packet
            ciphertext: ciphertext+GCM-tag bytes
            aad:        same AAD used during encryption

        Returns:
            plaintext bytes

        Raises:
            cryptography.exceptions.InvalidTag if authentication fails.
            Phase 1: returns *ciphertext* unchanged (nonce ignored).
        """
        if not self._enabled:
            return ciphertext

        return self._aesgcm.decrypt(nonce, ciphertext, aad)

    # ── key utilities ─────────────────────────────────────────────────────────

    @staticmethod
    def derive_key_from_passphrase(passphrase: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Phase 2 helper: derive a 32-byte AES key from a human passphrase
        using PBKDF2-HMAC-SHA256 (600 000 iterations per OWASP 2023).

        Returns (key, salt) — persist salt alongside the ciphertext.
        """
        import hashlib
        if salt is None:
            salt = os.urandom(16)
        key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), salt, 600_000, dklen=KEY_LENGTH)
        return key, salt
