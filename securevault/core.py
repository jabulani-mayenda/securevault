"""AES-GCM file encryption for SecureVault."""

from __future__ import annotations

import argparse
import hashlib
import io
import os
import secrets
import struct
import sys
import tempfile
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"SVLT2"
VERSION = 2
SALT_SIZE = 16
NONCE_PREFIX_SIZE = 8
NONCE_SIZE = 12
TAG_SIZE = 16
PBKDF2_ITERATIONS = 600_000
CHUNK_SIZE = 1024 * 1024
MAX_CHUNKS = (1 << 32) - 1
HEADER = struct.Struct(">5sBI16s8sI")
RECORD_LENGTH = struct.Struct(">I")


def _derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    if not password:
        raise ValueError("Password cannot be empty.")
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, iterations, dklen=32
    )


def _nonce(prefix: bytes, counter: int) -> bytes:
    if counter > MAX_CHUNKS:
        raise ValueError("The file contains too many encryption chunks.")
    return prefix + counter.to_bytes(4, byteorder="big")


def _chunk_aad(header: bytes, kind: bytes, counter: int, length: int) -> bytes:
    return header + kind + counter.to_bytes(4, byteorder="big") + length.to_bytes(
        4, byteorder="big"
    )


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        part = stream.read(size - len(result))
        if not part:
            raise ValueError("Encrypted file is truncated or malformed.")
        result.extend(part)
    return bytes(result)


def _encrypt_stream(source: BinaryIO, destination: BinaryIO, password: str) -> None:
    if not password:
        raise ValueError("Password cannot be empty.")

    salt = secrets.token_bytes(SALT_SIZE)
    nonce_prefix = secrets.token_bytes(NONCE_PREFIX_SIZE)
    header = HEADER.pack(
        MAGIC, VERSION, PBKDF2_ITERATIONS, salt, nonce_prefix, CHUNK_SIZE
    )
    cipher = AESGCM(_derive_key(password, salt, PBKDF2_ITERATIONS))
    destination.write(header)

    counter = 0
    while True:
        plaintext = source.read(CHUNK_SIZE)
        if not plaintext:
            break
        if counter >= MAX_CHUNKS:
            raise ValueError("The file is too large to encrypt.")

        aad = _chunk_aad(header, b"CHUNK", counter, len(plaintext))
        encrypted = cipher.encrypt(_nonce(nonce_prefix, counter), plaintext, aad)
        destination.write(RECORD_LENGTH.pack(len(plaintext)))
        destination.write(encrypted)
        counter += 1

    final_aad = _chunk_aad(header, b"FINAL", counter, 0)
    final_tag = cipher.encrypt(_nonce(nonce_prefix, counter), b"", final_aad)
    destination.write(RECORD_LENGTH.pack(0))
    destination.write(final_tag)


def _decrypt_stream(source: BinaryIO, destination: BinaryIO, password: str) -> None:
    if not password:
        raise ValueError("Password cannot be empty.")

    header_bytes = _read_exact(source, HEADER.size)
    magic, version, iterations, salt, nonce_prefix, chunk_size = HEADER.unpack(
        header_bytes
    )
    if magic != MAGIC:
        raise ValueError("Not a SecureVault AES-GCM encrypted file.")
    if version != VERSION:
        raise ValueError(f"Unsupported SecureVault version: {version}")
    if iterations != PBKDF2_ITERATIONS:
        raise ValueError("Unsupported key-derivation settings in encrypted file.")
    if chunk_size != CHUNK_SIZE:
        raise ValueError("Unsupported encryption chunk size.")

    cipher = AESGCM(_derive_key(password, salt, iterations))
    counter = 0

    while True:
        record_length = RECORD_LENGTH.unpack(_read_exact(source, RECORD_LENGTH.size))[0]
        if record_length == 0:
            final_tag = _read_exact(source, TAG_SIZE)
            final_aad = _chunk_aad(header_bytes, b"FINAL", counter, 0)
            try:
                cipher.decrypt(_nonce(nonce_prefix, counter), final_tag, final_aad)
            except InvalidTag as exc:
                raise ValueError(
                    "Incorrect password or encrypted file is damaged."
                ) from exc
            if source.read(1):
                raise ValueError("Unexpected data after encrypted file end marker.")
            return

        if record_length > chunk_size or counter >= MAX_CHUNKS:
            raise ValueError("Invalid encrypted file chunk.")

        encrypted = _read_exact(source, record_length + TAG_SIZE)
        aad = _chunk_aad(header_bytes, b"CHUNK", counter, record_length)
        try:
            plaintext = cipher.decrypt(
                _nonce(nonce_prefix, counter), encrypted, aad
            )
        except InvalidTag as exc:
            raise ValueError(
                "Incorrect password or encrypted file is damaged."
            ) from exc
        destination.write(plaintext)
        counter += 1


def encrypt_bytes(data: bytes, password: str) -> bytes:
    source = io.BytesIO(data)
    destination = io.BytesIO()
    _encrypt_stream(source, destination, password)
    return destination.getvalue()


def decrypt_bytes(data: bytes, password: str) -> bytes:
    source = io.BytesIO(data)
    destination = io.BytesIO()
    _decrypt_stream(source, destination, password)
    return destination.getvalue()


def _same_path(source: Path, destination: Path) -> bool:
    return source.resolve() == destination.resolve()


def _write_file_atomically(
    source_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    password: str,
    operation: str,
) -> Path:
    source = Path(source_path)
    destination = Path(output_path)
    if not source.is_file():
        raise ValueError(f"Input is not a file: {source}")
    if _same_path(source, destination):
        raise ValueError("Input and output paths must be different.")
    if not destination.parent.is_dir():
        raise ValueError(f"Output directory does not exist: {destination.parent}")

    temporary_path: str | None = None
    try:
        with source.open("rb") as input_stream:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=destination.parent,
                prefix=f".{destination.name}.",
                suffix=".tmp",
                delete=False,
            ) as output_stream:
                temporary_path = output_stream.name
                if operation == "encrypt":
                    _encrypt_stream(input_stream, output_stream, password)
                else:
                    _decrypt_stream(input_stream, output_stream, password)
                output_stream.flush()
                os.fsync(output_stream.fileno())

        os.replace(temporary_path, destination)
        temporary_path = None
        return destination
    finally:
        if temporary_path is not None:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass


def encrypt_file(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    password: str,
) -> Path:
    return _write_file_atomically(input_path, output_path, password, "encrypt")


def decrypt_file(
    input_path: str | os.PathLike[str],
    output_path: str | os.PathLike[str],
    password: str,
) -> Path:
    return _write_file_atomically(input_path, output_path, password, "decrypt")


def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="SecureVault: encrypt and decrypt files with AES-GCM."
    )
    parser.add_argument(
        "action",
        nargs="?",
        choices=["encrypt", "decrypt", "e", "d"],
        help="Operation to perform.",
    )
    parser.add_argument("input_file", nargs="?", help="Input file path.")
    parser.add_argument("output_file", nargs="?", help="Output file path.")
    parser.add_argument(
        "-k",
        "--key",
        "--password",
        dest="password",
        help="Password (if omitted, SecureVault prompts without displaying it).",
    )
    parser.add_argument(
        "-e", "--encrypt", dest="encrypt_flag", action="store_true", help="Encrypt."
    )
    parser.add_argument(
        "-d", "--decrypt", dest="decrypt_flag", action="store_true", help="Decrypt."
    )
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

    password = args.password
    if password is None:
        import getpass

        password = getpass.getpass("Password: ")

    try:
        if mode == "encrypt":
            encrypt_file(args.input_file, args.output_file, password)
            print(f"Encrypted: {args.input_file} -> {args.output_file}")
        else:
            decrypt_file(args.input_file, args.output_file, password)
            print(f"Decrypted: {args.input_file} -> {args.output_file}")
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 0
