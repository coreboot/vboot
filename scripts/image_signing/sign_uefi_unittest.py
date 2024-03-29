#!/usr/bin/env python3
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Tests for sign_uefi.py.

This is run as part of `make runtests`, or `make runtestscripts` if you
want something a little faster.
"""

from pathlib import Path
import tempfile
import unittest
from unittest import mock

import sign_uefi


class Test(unittest.TestCase):
    """Test sign_uefi.py."""

    def test_is_pkcs11_key_path(self):
        self.assertFalse(sign_uefi.is_pkcs11_key_path(Path("private_key.rsa")))

        self.assertTrue(
            sign_uefi.is_pkcs11_key_path("pkcs11:object=private_key")
        )

    @mock.patch("sign_uefi.inject_vbpubk")
    @mock.patch.object(sign_uefi.Signer, "create_detached_signature")
    @mock.patch.object(sign_uefi.Signer, "sign_efi_file")
    def test_successful_sign(
        self, mock_sign, mock_detached_sig, mock_inject_vbpubk
    ):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_dir = Path(tmp_dir)

            # Get key paths.
            keys = sign_uefi.Keys(
                private_key=tmp_dir / "private_key.rsa",
                sign_cert=tmp_dir / "sign_cert.pem",
                verify_cert=tmp_dir / "verify_cert.pem",
                kernel_subkey_vbpubk=tmp_dir / "kernel_subkey.vbpubk",
                crdyshim_private_key=tmp_dir / "crdyshim.priv.pem",
            )

            # Get target paths.
            target_dir = tmp_dir / "boot"
            syslinux_dir = target_dir / "syslinux"
            efi_boot_dir = target_dir / "efi/boot"

            # Make test dirs.
            syslinux_dir.mkdir(parents=True)
            efi_boot_dir.mkdir(parents=True)

            # Make key files.
            (keys.private_key).touch()
            (keys.sign_cert).touch()
            (keys.verify_cert).touch()
            (keys.kernel_subkey_vbpubk).touch()
            (keys.crdyshim_private_key).touch()

            # Make EFI files.
            (efi_boot_dir / "bootia32.efi").touch()
            (efi_boot_dir / "bootx64.efi").touch()
            (efi_boot_dir / "testia32.efi").touch()
            (efi_boot_dir / "testx64.efi").touch()
            (efi_boot_dir / "crdybootia32.efi").touch()
            (efi_boot_dir / "crdybootx64.efi").touch()
            (syslinux_dir / "vmlinuz.A").touch()
            (syslinux_dir / "vmlinuz.B").touch()
            (target_dir / "vmlinuz-5.10.156").touch()
            (target_dir / "vmlinuz").symlink_to(target_dir / "vmlinuz-5.10.156")

            # Set an EFI glob that matches only some of the EFI files.
            efi_glob = "test*.efi"

            # Sign, but with the actual signing mocked out.
            sign_uefi.sign_target_dir(target_dir, keys, efi_glob)

            # Check that the correct list of files got signed.
            self.assertEqual(
                mock_sign.call_args_list,
                [
                    # The test*.efi files match the glob,
                    # the boot*.efi files don't.
                    mock.call(efi_boot_dir / "testia32.efi"),
                    mock.call(efi_boot_dir / "testx64.efi"),
                    # Two syslinux kernels.
                    mock.call(syslinux_dir / "vmlinuz.A"),
                    mock.call(syslinux_dir / "vmlinuz.B"),
                    # One kernel in the target dir.
                    mock.call(target_dir / "vmlinuz-5.10.156"),
                ],
            )

            # Test signing a specific file.
            sign_uefi.sign_target_file(efi_boot_dir / "bootia32.efi", keys)

            # Check that we called the correct sign request.
            self.assertIn(
                [
                    mock.call(efi_boot_dir / "bootia32.efi"),
                ],
                mock_sign.call_args_list,
            )

            # Check that `inject_vbpubk` was called on both the crdyboot
            # executables.
            self.assertEqual(
                mock_inject_vbpubk.call_args_list,
                [
                    mock.call(efi_boot_dir / "crdybootia32.efi", keys),
                    mock.call(efi_boot_dir / "crdybootx64.efi", keys),
                ],
            )

            # Check that `create_detached_signature` was called on both
            # the crdyboot executables.
            self.assertEqual(
                mock_detached_sig.call_args_list,
                [
                    mock.call(efi_boot_dir / "crdybootia32.efi"),
                    mock.call(efi_boot_dir / "crdybootx64.efi"),
                ],
            )

    @mock.patch("sign_uefi.subprocess.run")
    def test_inject_vbpubk(self, mock_run):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_dir = Path(tmp_dir)

            keys = sign_uefi.Keys(
                private_key=None,
                sign_cert=None,
                verify_cert=None,
                kernel_subkey_vbpubk=tmp_dir / "kernel_subkey.vbpubk",
                crdyshim_private_key=None,
            )

            efi_file = tmp_dir / "test_efi_file"
            sign_uefi.inject_vbpubk(efi_file, keys)

            # Check that the expected command runs.
            self.assertEqual(
                mock_run.call_args_list,
                [
                    mock.call(
                        [
                            "sudo",
                            "objcopy",
                            "--update-section",
                            f".vbpubk={keys.kernel_subkey_vbpubk}",
                            efi_file,
                        ],
                        check=True,
                    )
                ],
            )

    @mock.patch("sign_uefi.subprocess.run")
    def test_create_detached_signature(self, mock_run):
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_dir = Path(tmp_dir)

            keys = sign_uefi.Keys(
                private_key=None,
                sign_cert=None,
                verify_cert=None,
                kernel_subkey_vbpubk=None,
                crdyshim_private_key=tmp_dir / "crdyshim.priv.pem",
            )
            signer = sign_uefi.Signer(tmp_dir, keys)

            efi_file = tmp_dir / "boot/crdybootx64.efi"
            signer.create_detached_signature(efi_file)

            # Check that the expected commands run.
            self.assertEqual(
                mock_run.call_args_list,
                [
                    mock.call(
                        [
                            "openssl",
                            "pkeyutl",
                            "-sign",
                            "-rawin",
                            "-in",
                            efi_file,
                            "-inkey",
                            keys.crdyshim_private_key,
                            "-out",
                            tmp_dir / "crdybootx64.sig",
                        ],
                        check=True,
                    ),
                    mock.call(
                        [
                            "sudo",
                            "cp",
                            tmp_dir / "crdybootx64.sig",
                            tmp_dir / "boot/crdybootx64.sig",
                        ],
                        check=True,
                    ),
                ],
            )


if __name__ == "__main__":
    unittest.main()
