"""Core encryption logic for SecureVault."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import secrets
from pathlib import Path

MAGIC = b"SVLT1"
VERSION = 1
SALT_SIZE = 16
NONCE_SIZE = 16
DIGEST_SIZE = 32
PBKDF2_ITERATIONS = 200_000


def derive_key(password: str, salt: bytes) -> tuple[bytes, bytes]:
    if not password:
        raise ValueError("Password cannot be empty.")
    expanded = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=64,
    )
    return expanded[:32], expanded[32:]


def keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    if length <= 0:
        return b""

    output = bytearray()
    counter = 0
    while len(output) < length:
        h = hashlib.sha256()
        h.update(key)
        h.update(nonce)
        h.update(counter.to_bytes(8, byteorder="big", signed=False))
        output.extend(h.digest())
        counter += 1
    return bytes(output[:length])


def encrypt_bytes(data: bytes, password: str) -> bytes:
    if not password:
        raise ValueError("Password cannot be empty.")

    salt = secrets.token_bytes(SALT_SIZE)
    nonce = secrets.token_bytes(NONCE_SIZE)
    enc_key, mac_key = derive_key(password, salt)

    cipher = bytes(a ^ b for a, b in zip(data, keystream(enc_key, nonce, len(data))))
    digest = hmac.new(mac_key, cipher + nonce, hashlib.sha256).digest()

    return MAGIC + bytes([VERSION]) + salt + nonce + cipher + digest


def decrypt_bytes(data: bytes, password: str) -> bytes:
    if not password:
        raise ValueError("Password cannot be empty.")

    minimum_size = len(MAGIC) + 1 + SALT_SIZE + NONCE_SIZE + DIGEST_SIZE
    if len(data) < minimum_size:
        raise ValueError("This file is not a valid SecureVault encrypted file.")

    if data[: len(MAGIC)] != MAGIC:
        raise ValueError("Missing or invalid SecureVault header.")

    version = data[len(MAGIC)]
    if version != VERSION:
        raise ValueError(f"Unsupported SecureVault version: {version}")

    salt_start = len(MAGIC) + 1
    nonce_start = salt_start + SALT_SIZE
    ciphertext_start = nonce_start + NONCE_SIZE
    ciphertext_end = len(data) - DIGEST_SIZE

    salt = data[salt_start:nonce_start]
    nonce = data[nonce_start:ciphertext_start]
    ciphertext = data[ciphertext_start:ciphertext_end]
    digest = data[-DIGEST_SIZE:]

    if len(nonce) != NONCE_SIZE:
        raise ValueError("Encrypted file is missing valid nonce data.")

    enc_key, mac_key = derive_key(password, salt)
    expected_digest = hmac.new(mac_key, ciphertext + nonce, hashlib.sha256).digest()
    if not hmac.compare_digest(digest, expected_digest):
        raise ValueError("Incorrect password or corrupted file.")

    plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream(enc_key, nonce, len(ciphertext))))
    return plaintext


def encrypt_file(input_path: str | os.PathLike[str], output_path: str | os.PathLike[str], password: str) -> Path:
    source = Path(input_path)
    destination = Path(output_path)
    destination.write_bytes(encrypt_bytes(source.read_bytes(), password))
    return destination


def decrypt_file(input_path: str | os.PathLike[str], output_path: str | os.PathLike[str], password: str) -> Path:
    source = Path(input_path)
    destination = Path(output_path)
    destination.write_bytes(decrypt_bytes(source.read_bytes(), password))
    return destination


def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SecureVault: encrypt and decrypt files.")
    parser.add_argument("action", nargs="?", choices=["encrypt", "decrypt", "e", "d"], help="Operation to perform.")
    parser.add_argument("input_file", nargs="?", help="Input file path.")
    parser.add_argument("output_file", nargs="?", help="Output file path.")
    parser.add_argument("-k", "--key", "--password", dest="password", help="Password used to encrypt or decrypt the file.")
    parser.add_argument("-e", "--encrypt", dest="encrypt_flag", action="store_true", help="Encrypt the input file.")
    parser.add_argument("-d", "--decrypt", dest="decrypt_flag", action="store_true", help="Decrypt the input file.")
    return parser


def run_cli(argv: list[str] | None = None) -> int:
    parser = build_cli_parser()
    args = parser.parse_args(argv)

    if args.encrypt_flag and args.decrypt_flag:
        parser.error("Choose either --encrypt or --decrypt, not both.")

    if args.action in {"e", "encrypt"}:
        mode = "encrypt"
    elif args.action in {"d", "decrypt"}:
        mode = "decrypt"
    elif args.encrypt_flag:
        mode = "encrypt"
    elif args.decrypt_flag:
        mode = "decrypt"
    else:
        parser.error("You must provide an action: encrypt|decrypt or -e/-d.")

    if not args.input_file or not args.output_file:
        parser.error("Both input_file and output_file are required.")
    if not args.password:
        parser.error("A password is required via --key/-k.")

    try:
        if mode == "encrypt":
            encrypt_file(args.input_file, args.output_file, args.password)
            print(f"Encrypted: {args.input_file} -> {args.output_file}")
        else:
            decrypt_file(args.input_file, args.output_file, args.password)
            print(f"Decrypted: {args.input_file} -> {args.output_file}")
    except Exception as exc:
        print(f"Error: {exc}", file=os.sys.stderr)
        return 1

    return 0
