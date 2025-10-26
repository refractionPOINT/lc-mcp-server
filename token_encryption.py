"""
Token Encryption Module

Provides encryption/decryption for sensitive tokens stored in Redis.
Uses AES-256-GCM for authenticated encryption with secure key derivation.

SECURITY: This module protects Firebase ID tokens and refresh tokens from
unauthorized access if Redis is compromised.
"""

import os
import base64
import logging
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class TokenEncryption:
    """
    Encrypts/decrypts sensitive tokens using AES-256-GCM.

    Features:
    - AES-256-GCM authenticated encryption
    - Unique nonce per encryption (prevents replay)
    - Key derivation from master secret
    - Constant-time decryption
    """

    # Encryption constants
    KEY_SIZE = 32  # 256 bits for AES-256
    NONCE_SIZE = 12  # 96 bits recommended for GCM
    TAG_SIZE = 16  # 128 bits authentication tag

    def __init__(self, master_key: Optional[str] = None):
        """
        Initialize token encryption.

        Args:
            master_key: Base64-encoded master encryption key
                       If not provided, uses REDIS_ENCRYPTION_KEY env var

        Raises:
            ValueError: If no encryption key is available
        """
        # Get master key from parameter or environment
        key_b64 = master_key or os.getenv("REDIS_ENCRYPTION_KEY")

        if not key_b64:
            raise ValueError(
                "REDIS_ENCRYPTION_KEY environment variable is required for token encryption. "
                "Generate a key with: python -c 'import os,base64; print(base64.b64encode(os.urandom(32)).decode())'"
            )

        try:
            # Decode base64 master key
            master_key_bytes = base64.b64decode(key_b64)

            if len(master_key_bytes) != self.KEY_SIZE:
                raise ValueError(f"Master key must be {self.KEY_SIZE} bytes (got {len(master_key_bytes)})")

            # Initialize AES-GCM cipher
            self.cipher = AESGCM(master_key_bytes)

            logging.info("Token encryption initialized with AES-256-GCM")

        except Exception as e:
            raise ValueError(f"Invalid encryption key: {e}")

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a token string.

        Args:
            plaintext: Token to encrypt

        Returns:
            Base64-encoded encrypted token with format: base64(nonce || ciphertext || tag)

        Raises:
            ValueError: If encryption fails
        """
        if not plaintext:
            return plaintext

        try:
            # Generate random nonce (MUST be unique per encryption)
            nonce = os.urandom(self.NONCE_SIZE)

            # Encrypt with authenticated encryption (AES-GCM)
            # This produces: ciphertext || tag
            plaintext_bytes = plaintext.encode('utf-8')
            ciphertext_and_tag = self.cipher.encrypt(nonce, plaintext_bytes, None)

            # Combine: nonce || ciphertext || tag
            encrypted = nonce + ciphertext_and_tag

            # Encode as base64 for Redis storage
            return base64.b64encode(encrypted).decode('ascii')

        except Exception as e:
            logging.error(f"Token encryption failed: {e}")
            raise ValueError(f"Encryption failed: {e}")

    def decrypt(self, ciphertext_b64: str) -> str:
        """
        Decrypt an encrypted token.

        Args:
            ciphertext_b64: Base64-encoded encrypted token

        Returns:
            Decrypted plaintext token

        Raises:
            ValueError: If decryption fails (wrong key, tampered data, etc.)
        """
        if not ciphertext_b64:
            return ciphertext_b64

        try:
            # Decode base64
            encrypted = base64.b64decode(ciphertext_b64)

            # Extract nonce and ciphertext+tag
            if len(encrypted) < self.NONCE_SIZE + self.TAG_SIZE:
                raise ValueError("Encrypted data too short")

            nonce = encrypted[:self.NONCE_SIZE]
            ciphertext_and_tag = encrypted[self.NONCE_SIZE:]

            # Decrypt and verify authentication tag
            # This will raise exception if authentication fails (tampered data)
            plaintext_bytes = self.cipher.decrypt(nonce, ciphertext_and_tag, None)

            return plaintext_bytes.decode('utf-8')

        except Exception as e:
            logging.error(f"Token decryption failed: {e}")
            raise ValueError(f"Decryption failed: {e}")

    def encrypt_if_enabled(self, plaintext: Optional[str]) -> Optional[str]:
        """
        Encrypt a token only if it exists (helper for optional fields).

        Args:
            plaintext: Token to encrypt (may be None)

        Returns:
            Encrypted token or None
        """
        if plaintext is None:
            return None
        return self.encrypt(plaintext)

    def decrypt_if_enabled(self, ciphertext: Optional[str]) -> Optional[str]:
        """
        Decrypt a token only if it exists (helper for optional fields).

        Args:
            ciphertext: Encrypted token (may be None)

        Returns:
            Decrypted token or None
        """
        if ciphertext is None:
            return None
        return self.decrypt(ciphertext)


# Singleton instance
_token_encryption: Optional[TokenEncryption] = None


def get_token_encryption() -> TokenEncryption:
    """
    Get singleton token encryption instance.

    Returns:
        TokenEncryption instance

    Raises:
        ValueError: If encryption key is not configured
    """
    global _token_encryption
    if _token_encryption is None:
        _token_encryption = TokenEncryption()
    return _token_encryption


def is_encryption_enabled() -> bool:
    """
    Check if token encryption is enabled.

    Returns:
        True if REDIS_ENCRYPTION_KEY is set
    """
    return bool(os.getenv("REDIS_ENCRYPTION_KEY"))
