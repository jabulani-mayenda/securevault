import tempfile
import unittest
from pathlib import Path

from securevault.core import (
    CHUNK_SIZE,
    HEADER,
    MAGIC,
    decrypt_bytes,
    decrypt_file,
    encrypt_bytes,
    encrypt_file,
)


class EncryptionTests(unittest.TestCase):
    def test_round_trip_empty_and_multiple_chunks(self) -> None:
        for data in (
            b"",
            b"Short file",
            b"x" * CHUNK_SIZE,
            bytes(range(256)) * (CHUNK_SIZE // 256 + 1),
        ):
            with self.subTest(length=len(data)):
                encrypted = encrypt_bytes(data, "strong-example-password")
                self.assertTrue(encrypted.startswith(MAGIC))
                self.assertEqual(
                    decrypt_bytes(encrypted, "strong-example-password"), data
                )

    def test_wrong_password_is_rejected(self) -> None:
        encrypted = encrypt_bytes(b"secret", "correct-password")

        with self.assertRaisesRegex(ValueError, "Incorrect password"):
            decrypt_bytes(encrypted, "wrong-password")

    def test_tampering_and_truncation_are_rejected(self) -> None:
        encrypted = encrypt_bytes(b"secret data", "password")
        tampered = bytearray(encrypted)
        tampered[-1] ^= 1

        with self.assertRaisesRegex(ValueError, "Incorrect password"):
            decrypt_bytes(bytes(tampered), "password")
        with self.assertRaisesRegex(ValueError, "truncated"):
            decrypt_bytes(encrypted[:-1], "password")

    def test_legacy_custom_format_is_rejected(self) -> None:
        legacy_header = MAGIC + b"\x01" + bytes(HEADER.size - len(MAGIC) - 1)

        with self.assertRaisesRegex(ValueError, "Unsupported SecureVault version"):
            decrypt_bytes(legacy_header, "password")

    def test_file_round_trip_streams_data(self) -> None:
        data = b"streamed content" * 100_000
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source.bin"
            encrypted = Path(directory) / "source.securevault"
            restored = Path(directory) / "restored.bin"
            source.write_bytes(data)

            encrypt_file(source, encrypted, "example-password")
            decrypt_file(encrypted, restored, "example-password")

            self.assertEqual(restored.read_bytes(), data)

    def test_failed_decryption_does_not_replace_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "encrypted.bin"
            destination = Path(directory) / "important.txt"
            source.write_bytes(encrypt_bytes(b"secret", "correct-password"))
            destination.write_bytes(b"keep this file")

            with self.assertRaisesRegex(ValueError, "Incorrect password"):
                decrypt_file(source, destination, "wrong-password")

            self.assertEqual(destination.read_bytes(), b"keep this file")

    def test_input_and_output_must_be_different(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.txt"
            path.write_bytes(b"content")

            with self.assertRaisesRegex(ValueError, "must be different"):
                encrypt_file(path, path, "password")


if __name__ == "__main__":
    unittest.main()
