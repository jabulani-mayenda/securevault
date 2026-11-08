# SecureVault

SecureVault is a desktop-friendly Python app for encrypting and decrypting files with a password. It is designed to be simple to run, easy to expand, and secure enough for everyday local file protection.

## Features

- Password-based file encryption and decryption
- Random salt and nonce per file
- PBKDF2-HMAC-SHA256 key derivation
- File integrity verification using HMAC-SHA256
- Command-line app ready for future GUI or web expansion

## Run it

```bash
python app.py encrypt input.txt encrypted.bin --key mysecretpassword
python app.py decrypt encrypted.bin restored.txt --key mysecretpassword
```

Short flags also work:

```bash
python app.py -e input.txt encrypted.bin -k mysecretpassword
python app.py -d encrypted.bin restored.txt -k mysecretpassword
```

## Security notes

- Use a strong password with at least 12+ characters.
- Keep the password private; the encrypted file itself does not contain a recoverable key.
- This is a local file protection utility, not a cloud backup or multi-user authentication system.

## Project structure

- `app.py` — command-line entry point
- `file_encryptor.py` — core encryption/decryption logic
- `README.md` — quick start and documentation
