# SecureVault

SecureVault is a local desktop and command-line app for password-based file encryption and decryption.

## Features

- AES-256-GCM authenticated encryption from the maintained `cryptography` package
- Password-based key derivation with PBKDF2-HMAC-SHA256 and a random 16-byte salt
- Fresh random nonce prefix for every encrypted file and a distinct nonce for every 1 MiB chunk
- Chunked file processing, so large files do not need to fit in memory
- Authentication of each chunk and an authenticated end marker to detect tampering and truncation
- Atomic output replacement: a failed decrypt does not leave a partial plaintext output
- Desktop GUI and command-line interfaces

## Requirements

- Python 3.10 or later
- Tkinter for the desktop GUI (included with most standard Python installers)

Install the Python dependency:

```powershell
python -m pip install -r requirements.txt
```

## Run the desktop app

```powershell
python launch_gui.py
```

Select an input file, choose an output path, enter a password, and click **Encrypt File** or **Decrypt File**. The app asks before replacing an existing output file.

## Run from the command line

SecureVault prompts for the password without displaying it when `--key` is omitted:

```powershell
python app.py encrypt input.txt input.txt.securevault
python app.py decrypt input.txt.securevault restored.txt
```

For scripts, a password can be passed explicitly (which may expose it in shell history or process listings):

```powershell
python app.py encrypt input.txt input.txt.securevault --key "a-long-unique-password"
python app.py decrypt input.txt.securevault restored.txt --key "a-long-unique-password"
```

## Test

```powershell
python -m unittest discover -s tests -v
```

## Encrypted file format and compatibility

The current format is version 2 (`SVLT2`). Each file has a random salt and nonce prefix in its header. PBKDF2 derives a 256-bit AES key from the password; AES-GCM encrypts and authenticates each chunk, and authenticates the final marker. A wrong password, modified ciphertext, or truncated file is rejected.

This version cannot decrypt files produced by the earlier custom-encryption prototype (the old `SVLT2` header with format-version byte `1`, or the still earlier `FCRY1` format). Keep original unencrypted copies of any files encrypted with those prototypes; do not assume the old formats are secure or compatible.

## Security notes

- Use a unique, long password and keep a safe backup; a lost password cannot be recovered.
- Do not use the example password above for real data.
- This tool protects file contents, not filenames, file sizes, backups, or copies outside the selected output path.
- AES-GCM is provided by the `cryptography` library; SecureVault does not implement AES itself.
- Review the source and your threat model before relying on any software for sensitive data.
