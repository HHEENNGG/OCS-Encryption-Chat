"""Sync the native/ tree to an ASCII-only build directory.

GNU ld (rustup windows-gnu toolchain) cannot open output files under non-ASCII
(e.g. Chinese) paths. This script copies native/ (excluding target/) to a
plain-ASCII directory so cargo can build there. The relative ../vendor layout
is preserved.

Usage:
    python scripts/copy_native.py [SOURCE_NATIVE_DIR] [TARGET_ASCII_DIR]

Defaults:
    SOURCE_NATIVE_DIR = <repo>/native   (relative to this script)
    TARGET_ASCII_DIR  = %USERPROFILE%/ocs-native  (or $HOME/ocs-native)
"""
import os
import shutil
import sys
from pathlib import Path

repo_native = Path(__file__).resolve().parent.parent / "native"
home = Path(os.environ.get("USERPROFILE") or os.environ.get("HOME") or Path.home())

src = Path(sys.argv[1]) if len(sys.argv) > 1 else repo_native
dst = Path(sys.argv[2]) if len(sys.argv) > 2 else home / "ocs-native"

if not src.is_dir():
    raise SystemExit(f"source native dir not found: {src}")
if not str(dst).isascii():
    raise SystemExit(f"target must be an ASCII path: {dst}")

shutil.copytree(src, dst, ignore=shutil.ignore_patterns("target"), dirs_exist_ok=True)
print(f"copied {src} -> {dst}")