"""
================================================================
crypto_utils.py (backward-compatible wrapper)
================================================================
Existing code imported `encrypt_file` / `decrypt_file` from this
module. It now delegates to the upgraded crypto.py pipeline.
"""

from crypto import decrypt_file, encrypt_file  # noqa: F401
