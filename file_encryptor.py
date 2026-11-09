"""Compatibility imports for older scripts using ``file_encryptor``."""

from securevault.core import decrypt_bytes, decrypt_file, encrypt_bytes, encrypt_file
from securevault.core import run_cli as main

__all__ = ["encrypt_bytes", "decrypt_bytes", "encrypt_file", "decrypt_file", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
