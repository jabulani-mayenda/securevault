from securevault.core import decrypt_bytes, encrypt_bytes


def test_encrypt_decrypt_round_trip() -> None:
    data = b"Hello SecureVault!\nThis is a test file."
    password = "super-secret-password"

    encrypted = encrypt_bytes(data, password)
    decrypted = decrypt_bytes(encrypted, password)

    assert decrypted == data
    assert encrypted.startswith(b"SVLT1")


def test_wrong_password_fails() -> None:
    data = b"Some data"
    encrypted = encrypt_bytes(data, "password1")

    try:
        decrypt_bytes(encrypted, "password2")
        assert False, "Expected ValueError for wrong password"
    except ValueError:
        pass
