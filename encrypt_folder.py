"""
Folder encryption script for cybersecurity class.

Features:
- Takes a folder path, zips all its contents, and encrypts the zip using
  the `cryptography` library (Fernet).
- Writes the encrypted archive as a single `.enc` file.
- Drops a text file into the target folder with a short message and the
  generated encryption key (base64 URL-safe string).
- Supports a decrypt mode that uses the stored key to restore the files
  into a new folder.

Requirements:
- Python 3.8+
- cryptography  (install with: pip install cryptography)
"""

from __future__ import annotations

import argparse
import io
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import zipfile

from cryptography.fernet import Fernet, InvalidToken


DEFAULT_INFO_FILENAME = "encryption_info.txt"


@dataclass
class EncryptConfig:
    folder: Path
    output_file: Path
    info_file: Path


@dataclass
class DecryptConfig:
    folder: Path
    encrypted_file: Path
    info_file: Path
    output_folder: Path


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Zip and encrypt a folder using Fernet (AES-based) encryption, "
            "and optionally decrypt it again."
        )
    )

    parser.add_argument(
        "--folder",
        type=str,
        required=True,
        help="Path to the folder to encrypt (and where the info file will be written).",
    )
    parser.add_argument(
        "--output",
        type=str,
        help=(
            "Path for the encrypted archive file. "
            "Defaults to <folder>.zip.enc next to the folder."
        ),
    )
    parser.add_argument(
        "--decrypt",
        action="store_true",
        help="Run in decrypt mode instead of encrypt mode.",
    )
    parser.add_argument(
        "--encrypted-file",
        type=str,
        help=(
            "Path to the encrypted .enc file (used in decrypt mode). "
            "Defaults to the same as --output or <folder>.zip.enc."
        ),
    )
    parser.add_argument(
        "--output-folder",
        type=str,
        help=(
            "Output folder for decrypted contents (decrypt mode). "
            "Defaults to <folder>_decrypted."
        ),
    )
    parser.add_argument(
        "--info-file",
        type=str,
        help=(
            "Path to the encryption info text file. "
            f"Defaults to <folder>/{DEFAULT_INFO_FILENAME}."
        ),
    )

    return parser.parse_args(argv)


def build_encrypt_config(args: argparse.Namespace) -> EncryptConfig:
    folder = Path(args.folder).expanduser().resolve()
    if not folder.exists() or not folder.is_dir():
        raise SystemExit(f"Folder does not exist or is not a directory: {folder}")

    if args.output:
        output_file = Path(args.output).expanduser().resolve()
    else:
        output_file = folder.with_suffix("")  # strip any trailing slash
        output_file = output_file.parent / f"{folder.name}.zip.enc"

    if args.info_file:
        info_file = Path(args.info_file).expanduser().resolve()
    else:
        info_file = folder / DEFAULT_INFO_FILENAME

    return EncryptConfig(folder=folder, output_file=output_file, info_file=info_file)


def build_decrypt_config(args: argparse.Namespace) -> DecryptConfig:
    folder = Path(args.folder).expanduser().resolve()
    if not folder.exists() or not folder.is_dir():
        raise SystemExit(f"Folder does not exist or is not a directory: {folder}")

    if args.encrypted_file:
        encrypted_file = Path(args.encrypted_file).expanduser().resolve()
    elif args.output:
        encrypted_file = Path(args.output).expanduser().resolve()
    else:
        encrypted_file = folder.with_suffix("")
        encrypted_file = encrypted_file.parent / f"{folder.name}.zip.enc"

    if not encrypted_file.exists():
        raise SystemExit(f"Encrypted file not found: {encrypted_file}")

    if args.info_file:
        info_file = Path(args.info_file).expanduser().resolve()
    else:
        info_file = folder / DEFAULT_INFO_FILENAME

    if not info_file.exists():
        raise SystemExit(f"Encryption info file not found: {info_file}")

    if args.output_folder:
        output_folder = Path(args.output_folder).expanduser().resolve()
    else:
        output_folder = folder.parent / f"{folder.name}_decrypted"

    return DecryptConfig(
        folder=folder,
        encrypted_file=encrypted_file,
        info_file=info_file,
        output_folder=output_folder,
    )


def zip_folder_to_bytes(folder: Path) -> bytes:
    """
    Create a zip archive of the given folder and return its bytes.

    The archive stores paths relative to the folder root.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(folder):
            root_path = Path(root)
            for name in files:
                file_path = root_path / name
                # Store relative to the folder root
                rel_path = file_path.relative_to(folder)
                zf.write(file_path, arcname=str(rel_path))
    return buffer.getvalue()


def generate_key() -> bytes:
    """Generate a new random Fernet key."""
    return Fernet.generate_key()


def write_info_file(info_path: Path, key: bytes, encrypted_file: Path) -> None:
    """
    Write a text file with a brief explanation and the encryption key.
    """
    info_path.parent.mkdir(parents=True, exist_ok=True)
    message_lines = [
        "This folder has been encrypted as part of a cybersecurity class exercise.",
        f"The encrypted archive file is: {encrypted_file}",
        "",
        "Use the Python script `encrypt_folder.py` together with the key below",
        "to decrypt the archive and restore the original files.",
        "",
        "Encryption key (Fernet, base64 URL-safe):",
        key.decode("utf-8"),
        "",
    ]
    info_path.write_text("\n".join(message_lines), encoding="utf-8")


def read_key_from_info_file(info_path: Path) -> bytes:
    """
    Read the encryption key from the info file.

    The function looks for a non-empty line after the line that starts with
    'Encryption key' and returns it as bytes.
    """
    text = info_path.read_text(encoding="utf-8")
    lines = [line.rstrip("\n") for line in text.splitlines()]

    for idx, line in enumerate(lines):
        if line.strip().lower().startswith("encryption key"):
            # Next non-empty line should be the key
            for next_line in lines[idx + 1 :]:
                key_str = next_line.strip()
                if key_str:
                    return key_str.encode("utf-8")
            break

    raise SystemExit(
        f"Could not find encryption key in info file: {info_path}. "
        "Expected a non-empty line after the 'Encryption key' line."
    )


def encrypt_folder(config: EncryptConfig) -> None:
    print(f"[+] Zipping folder: {config.folder}")
    zip_bytes = zip_folder_to_bytes(config.folder)

    print("[+] Generating encryption key")
    key = generate_key()
    fernet = Fernet(key)

    print(f"[+] Encrypting zip archive ({len(zip_bytes)} bytes)")
    token = fernet.encrypt(zip_bytes)

    config.output_file.parent.mkdir(parents=True, exist_ok=True)
    config.output_file.write_bytes(token)
    print(f"[+] Encrypted archive written to: {config.output_file}")

    print(f"[+] Writing encryption info file to: {config.info_file}")
    write_info_file(config.info_file, key=key, encrypted_file=config.output_file)
    print("[+] Done.")


def decrypt_folder(config: DecryptConfig) -> None:
    print(f"[+] Reading encryption key from: {config.info_file}")
    key = read_key_from_info_file(config.info_file)
    fernet = Fernet(key)

    print(f"[+] Reading encrypted archive: {config.encrypted_file}")
    encrypted_bytes = config.encrypted_file.read_bytes()

    print("[+] Decrypting archive")
    try:
        zip_bytes = fernet.decrypt(encrypted_bytes)
    except InvalidToken as exc:
        raise SystemExit(f"Decryption failed: invalid key or corrupted data ({exc})")

    print(f"[+] Extracting zip contents to: {config.output_folder}")
    config.output_folder.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(zip_bytes), mode="r") as zf:
        zf.extractall(config.output_folder)

    print("[+] Decryption complete.")


def main(argv: Optional[list[str]] = None) -> None:
    args = parse_args(argv)
    if args.decrypt:
        cfg = build_decrypt_config(args)
        decrypt_folder(cfg)
    else:
        cfg = build_encrypt_config(args)
        encrypt_folder(cfg)


if __name__ == "__main__":
    main()

