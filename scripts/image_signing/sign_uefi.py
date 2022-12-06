#!/usr/bin/env python3
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Sign the UEFI binaries in the target directory.

The target directory can be either the root of ESP or /boot of root filesystem.
"""

import argparse
import logging
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import List, Optional


def ensure_executable_available(name):
    """Exit non-zero if the given executable isn't in $PATH.

    Args:
        name: An executable's file name.
    """
    if not shutil.which(name):
        sys.exit(f"Cannot sign UEFI binaries ({name} not found)")


def ensure_file_exists(path, message):
    """Exit non-zero if the given file doesn't exist.

    Args:
        path: Path to a file.
        message: Error message that will be printed if the file doesn't exist.
    """
    if not path.is_file():
        sys.exit(f"{message}: {path}")


class Signer:
    """EFI file signer.

    Attributes:
        temp_dir: Path of a temporary directory used as a workspace.
        priv_key: Path of the private key.
        sign_cert: Path of the signing certificate.
        verify_cert: Path of the certificate used to verify the signature.
    """

    def __init__(self, temp_dir, priv_key, sign_cert, verify_cert):
        self.temp_dir = temp_dir
        self.priv_key = priv_key
        self.sign_cert = sign_cert
        self.verify_cert = verify_cert

    def sign_efi_file(self, target):
        """Sign an EFI binary file, if possible.

        Args:
            target: Path of the file to sign.
        """
        logging.info("signing efi file %s", target)

        # Allow this to fail, as there maybe no current signature.
        subprocess.run(["sudo", "sbattach", "--remove", target], check=False)

        signed_file = self.temp_dir / target.name
        try:
            subprocess.run(
                [
                    "sbsign",
                    "--key",
                    self.priv_key,
                    "--cert",
                    self.sign_cert,
                    "--output",
                    signed_file,
                    target,
                ],
                check=True,
            )
        except subprocess.CalledProcessError:
            logging.warning("cannot sign %s", target)
            return

        subprocess.run(
            ["sudo", "cp", "--force", signed_file, target], check=True
        )
        try:
            subprocess.run(
                ["sbverify", "--cert", self.verify_cert, target], check=True
            )
        except subprocess.CalledProcessError:
            sys.exit("Verification failed")


def sign_target_dir(target_dir, key_dir, efi_glob):
    """Sign various EFI files under |target_dir|.

    Args:
        target_dir: Path of a boot directory. This can be either the
            root of the ESP or /boot of the root filesystem.
        key_dir: Path of a directory containing the key and cert files.
        efi_glob: Glob pattern of EFI files to sign, e.g. "*.efi".
    """
    bootloader_dir = target_dir / "efi/boot"
    syslinux_dir = target_dir / "syslinux"
    kernel_dir = target_dir

    verify_cert = key_dir / "db/db.pem"
    ensure_file_exists(verify_cert, "No verification cert")

    sign_cert = key_dir / "db/db.children/db_child.pem"
    ensure_file_exists(sign_cert, "No signing cert")

    sign_key = key_dir / "db/db.children/db_child.rsa"
    ensure_file_exists(sign_key, "No signing key")

    with tempfile.TemporaryDirectory() as working_dir:
        signer = Signer(Path(working_dir), sign_key, sign_cert, verify_cert)

        for efi_file in sorted(bootloader_dir.glob(efi_glob)):
            if efi_file.is_file():
                signer.sign_efi_file(efi_file)

        for syslinux_kernel_file in sorted(syslinux_dir.glob("vmlinuz.?")):
            if syslinux_kernel_file.is_file():
                signer.sign_efi_file(syslinux_kernel_file)

        kernel_file = (kernel_dir / "vmlinuz").resolve()
        if kernel_file.is_file():
            signer.sign_efi_file(kernel_file)


def get_parser() -> argparse.ArgumentParser:
    """Get CLI parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "target_dir",
        type=Path,
        help="Path of a boot directory, either the root of the ESP or "
        "/boot of the root filesystem",
    )
    parser.add_argument(
        "key_dir",
        type=Path,
        help="Path of a directory containing the key and cert files",
    )
    parser.add_argument(
        "efi_glob", help="Glob pattern of EFI files to sign, e.g. '*.efi'"
    )
    return parser


def main(argv: Optional[List[str]] = None) -> Optional[int]:
    """Sign UEFI binaries.

    Args:
        argv: Command-line arguments.
    """
    logging.basicConfig(level=logging.INFO)

    parser = get_parser()
    opts = parser.parse_args(argv)

    for tool in ("sbattach", "sbsign", "sbverify"):
        ensure_executable_available(tool)

    sign_target_dir(opts.target_dir, opts.key_dir, opts.efi_glob)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
