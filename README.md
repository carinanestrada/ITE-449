## ITE-449 Folder Encryption Project

This repository is for a **school project in ITE 449 (Infrastructure / Cybersecurity)**.  
The goal is to **simulate ransomware-style file encryption in a controlled lab environment**.

### Project overview

- **Script**: `encrypt_folder.py`
- **Language**: Python 3
- **Main purpose**:  
  - Take a target folder, zip all its contents, and encrypt the zip archive using the `cryptography` library (Fernet – AES-based, authenticated encryption).
  - Drop a text file in the same folder containing:
    - A short message explaining that the files have been encrypted for a class exercise.
    - The encryption key needed to decrypt the archive.
  - Optionally decrypt the archive and restore the files using the stored key.

> **Important:** This project is for **educational use only** in ITE 449.  
> Do **not** run this script against systems, data, or users that you do not own or have explicit permission to test.

### Requirements

- Python 3.8 or later
- `cryptography` library:

```bash
pip install cryptography
```

### How to encrypt a folder

From the repository root:

```bash
python encrypt_folder.py --folder /path/to/your/folder
```

What this does:

- Creates an encrypted archive: `/path/to/your/folder.zip.enc` (by default).
- Writes `encryption_info.txt` inside `/path/to/your/folder` with:
  - A short explanation that this is an ITE 449 cybersecurity exercise.
  - The Fernet encryption key (base64 URL-safe string).

You can customize:

- `--output`: where to write the `.enc` file.
- `--info-file`: where to write the info/key text file.

### How to decrypt a folder

Assuming you already ran the encryption step and have:
- The encrypted file (e.g., `/path/to/your/folder.zip.enc`)
- The info file with the key (e.g., `/path/to/your/folder/encryption_info.txt`)

Run:

```bash
python encrypt_folder.py --folder /path/to/your/folder --decrypt
```

By default this will:

- Read the key from `encryption_info.txt`.
- Decrypt the encrypted archive.
- Extract the original files into `/path/to/your/folder_decrypted`.

You can customize:

- `--encrypted-file`: path to the `.enc` file to decrypt.
- `--output-folder`: where to extract the decrypted files.
- `--info-file`: path to the info file if you moved or renamed it.

### Security notes (for write-ups)

- This script demonstrates:
  - Symmetric encryption of file data using Fernet (AES + HMAC).
  - Basic ransomware-like behavior (encrypt files, store a key and message).
- **Deliberate weakness**: Storing the encryption key in a text file alongside the encrypted data is **not secure** in the real world.  
  It is done here on purpose to:
  - Keep the lab simple.
  - Make it easy for instructors to verify and grade your work.
