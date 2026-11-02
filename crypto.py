"""
================================================================
CRYPTO MODULE
================================================================
Upgraded encryption pipeline:

  Original file
      |
      v
  SHA-256 digest  (integrity anchor, stored in database)
      |
      v
  AES-256-GCM with a RANDOM per-file key
      |  (file key is wrapped/encrypted by the MASTER KEY
      |   -> envelope encryption, key-rotation ready)
      |
      v
  HMAC-SHA256 over the ciphertext with the master key
      |
      v
  Split into N fragments  (uploaded separately to S3)

Legacy files (old static-key EAX format) remain decryptable
for backward compatibility.
================================================================
"""

import hashlib
import hmac
import os

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from config import Config

# ------------------------------------------------------------
# Format constants
# ------------------------------------------------------------

MAGIC = b"SCDP1"
VERSION = 1

# Header layout:
#   magic(5) + version(1) + wrap_nonce(12) + wrap_tag(16)
#   + wrapped_key(32) + mac(32) + file_nonce(12) + file_tag(16)
HEADER_LEN = 5 + 1 + 12 + 16 + 32 + 32 + 12 + 16

# Legacy static key kept ONLY for decrypting old .enc files
LEGACY_KEY = b"1234567890123456"

# Master key is stored outside the repo (keys/master.key) or in .env
MASTER_KEY_PATH = os.path.join(
    os.path.abspath(os.path.dirname(__file__)),
    "keys",
    "master.key",
)


class CryptoError(Exception):
    """Base crypto exception."""


class IntegrityError(CryptoError):
    """Raised when data fails HMAC/GCM/SHA-256 verification."""


# ------------------------------------------------------------
# Master key management (key-rotation ready)
# ------------------------------------------------------------

def get_master_key():
    """Returns the 32-byte AES master key."""
    env_key = getattr(Config, "MASTER_KEY", "") or ""
    if env_key:
        cleaned = env_key.strip()
        if len(cleaned) == 64:
            try:
                return bytes.fromhex(cleaned)
            except ValueError:
                pass
        if len(cleaned) in (16, 24, 32):
            return cleaned.encode("utf-8")
        raise CryptoError(
            "MASTER_KEY in .env must be 64 hex characters (32 bytes)."
        )

    os.makedirs(os.path.dirname(MASTER_KEY_PATH), exist_ok=True)
    if os.path.exists(MASTER_KEY_PATH):
        with open(MASTER_KEY_PATH, "rb") as f:
            return f.read()

    key = get_random_bytes(32)
    with open(MASTER_KEY_PATH, "wb") as f:
        f.write(key)
    return key


# ------------------------------------------------------------
# Encryption
# ------------------------------------------------------------

def encrypt_bytes(data):
    """Encrypts bytes with envelope encryption. Returns binary blob."""
    master_key = get_master_key()

    # 1) random per-file data key
    file_key = get_random_bytes(32)

    # 2) wrap the file key with the master key
    wrap_nonce = get_random_bytes(12)
    wrap_cipher = AES.new(master_key, AES.MODE_GCM, nonce=wrap_nonce)
    wrapped_key, wrap_tag = wrap_cipher.encrypt_and_digest(file_key)

    # 3) encrypt the data with the file key (AES-256-GCM)
    file_nonce = get_random_bytes(12)
    cipher = AES.new(file_key, AES.MODE_GCM, nonce=file_nonce)
    ciphertext, file_tag = cipher.encrypt_and_digest(data)

    # 4) HMAC-SHA256 integrity anchor.
    #    Covers the entire header + ciphertext so that ANY modification
    #    (header field or payload) is immediately detectable.
    mac_input = (
        wrap_nonce
        + wrap_tag
        + wrapped_key
        + file_nonce
        + file_tag
        + ciphertext
    )
    mac = hmac.new(master_key, mac_input, hashlib.sha256).digest()

    header = (
        MAGIC
        + bytes([VERSION])
        + wrap_nonce
        + wrap_tag
        + wrapped_key
        + mac
        + file_nonce
        + file_tag
    )
    return header + ciphertext


def encrypt_file(input_path, output_path=None):
    """Encrypts a file. Returns path to the encrypted file."""
    with open(input_path, "rb") as f:
        data = f.read()

    blob = encrypt_bytes(data)
    out = output_path or input_path + ".enc"
    with open(out, "wb") as f:
        f.write(blob)
    return out


# ------------------------------------------------------------
# Decryption
# ------------------------------------------------------------

def decrypt_bytes(blob):
    """Decrypts a blob. Supports new envelope + legacy formats."""
    if blob[: len(MAGIC)] == MAGIC:
        return _decrypt_v1(blob)
    return _decrypt_legacy(blob)


def _decrypt_v1(blob):
    if len(blob) < HEADER_LEN:
        raise IntegrityError("Encrypted payload is too short.")

    master_key = get_master_key()

    pos = len(MAGIC)
    version = blob[pos]
    pos += 1
    if version != VERSION:
        raise IntegrityError(
            "Unsupported encryption version (tampered or future format)."
        )
    wrap_nonce = blob[pos:pos + 12]
    pos += 12
    wrap_tag = blob[pos:pos + 16]
    pos += 16
    wrapped_key = blob[pos:pos + 32]
    pos += 32
    mac = blob[pos:pos + 32]
    pos += 32
    file_nonce = blob[pos:pos + 12]
    pos += 12
    file_tag = blob[pos:pos + 16]
    pos += 16
    ciphertext = blob[pos:]

    # HMAC verification first - detects any tampering (header or payload)
    mac_input = (
        wrap_nonce
        + wrap_tag
        + wrapped_key
        + file_nonce
        + file_tag
        + ciphertext
    )
    expected_mac = hmac.new(
        master_key, mac_input, hashlib.sha256
    ).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise IntegrityError(
            "HMAC verification failed - ciphertext may be tampered."
        )

    # unwrap the per-file key
    try:
        wrap_cipher = AES.new(master_key, AES.MODE_GCM, nonce=wrap_nonce)
        file_key = wrap_cipher.decrypt_and_verify(wrapped_key, wrap_tag)
    except ValueError as exc:
        raise IntegrityError(
            "Key wrapper verification failed."
        ) from exc

    # decrypt + GCM tag verification
    try:
        cipher = AES.new(file_key, AES.MODE_GCM, nonce=file_nonce)
        return cipher.decrypt_and_verify(ciphertext, file_tag)
    except ValueError as exc:
        raise IntegrityError(
            "GCM tag verification failed - data is corrupted."
        ) from exc


def _decrypt_legacy(blob):
    """Decrypts legacy files: nonce(16) + tag(16) + ciphertext (EAX)."""
    if len(blob) < 32:
        raise IntegrityError("Legacy encrypted payload is too short.")
    nonce = blob[:16]
    tag = blob[16:32]
    ciphertext = blob[32:]
    try:
        cipher = AES.new(LEGACY_KEY, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise IntegrityError(
            "Legacy GCM/EAX verification failed."
        ) from exc


def decrypt_file(encrypted_path, output_path=None):
    """Decrypts a file. Returns path to the decrypted file."""
    with open(encrypted_path, "rb") as f:
        blob = f.read()

    plaintext = decrypt_bytes(blob)
    out = output_path or encrypted_path.replace(".enc", "")
    with open(out, "wb") as f:
        f.write(plaintext)
    return out


# ------------------------------------------------------------
# SHA-256 hashing
# ------------------------------------------------------------

def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    """Streaming SHA-256 of a file. Returns hex digest."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ------------------------------------------------------------
# Fragmentation
# ------------------------------------------------------------

def split_file(path, part_size=None):
    """
    Splits an (already encrypted) file into fragments.
    Returns a list of fragment file paths.
    """
    part_size = part_size or getattr(
        Config, "FRAGMENT_SIZE_BYTES", 4 * 1024 * 1024
    )
    parts = []
    index = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(part_size)
            if not chunk:
                break
            part_path = f"{path}.part{index}"
            with open(part_path, "wb") as pf:
                pf.write(chunk)
            parts.append(part_path)
            index += 1

    # an empty encrypted file still produces one fragment
    if not parts:
        part_path = f"{path}.part0"
        with open(part_path, "wb"):
            pass
        parts.append(part_path)

    return parts


def merge_files(part_paths, output_path):
    """Merges fragment files back into one file. Returns output path."""
    with open(output_path, "wb") as out:
        for part in part_paths:
            with open(part, "rb") as f:
                out.write(f.read())
    return output_path
