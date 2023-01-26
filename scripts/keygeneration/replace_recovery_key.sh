#!/bin/bash
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Script to replace the recovery key with a newly generated one. See usage().

# Load common constants and variables.
. "$(dirname "$0")/common.sh"

# Abort on errors.
set -e

usage() {
  cat <<EOF
Usage: $0 <keyset directory>

Creates a new recovery_key (incl. dependent kernel data keys) and renames the
old one to recovery_key.v1. This is useful when we want to prevent units
fabricated in the future from booting current recovery or factory shim images,
but still want future recovery and factory shim images to be able to run on
both new units and those that had already been shipped with the old recovery
key.
EOF
}

# The key versions for recovery keys and dependent kernel data keys are unused,
# since there is no rollback protection for them. Set the new key versions to 2
# so that they can be easily told apart from the old keys (which would have been
# built with version 1) when reading them from a device.
#
# (Note that for miniOS kernels, the kernel version *is* used for rollback
# protection, but the kernel key version is not, so we are free to do this.
# Kernel versions are set at kernel signing time, so they don't matter here.)
VERSION="2"

main() {
  local ext
  local k

  KEY_DIR=$1

  if [ $# -ne 1 ]; then
    usage
    exit 1
  fi

  cd "${KEY_DIR}"

  if [[ -e "recovery_key.v1.vbpubk" ]] || [[ -e "recovery_key.v1.vbprivk" ]]; then
    die "recovery_key.v1 already exists!"
  fi

  info "Moving old recovery key to recovery_key.v1."

  for ext in "vbpubk" "vbprivk"; do
    mv "recovery_key.${ext}" "recovery_key.v1.${ext}"
  done

  info "Backing up old kernel data keys (no longer needed) as XXX.old.v1.YYY."

  for k in "recovery_kernel" "installer_kernel" "minios_kernel"; do
    for ext in "vbpubk" "vbprivk"; do
      mv "${k}_data_key.${ext}" "${k}_data_key.old.v1.${ext}"
    done
    mv "${k}.keyblock" "${k}.old.v1.keyblock"
  done

  info "Creating new recovery key."

  make_pair recovery_key "${RECOVERY_KEY_ALGOID}" "${VERSION}"

  info "Creating new recovery, minios and installer kernel data keys."

  make_pair recovery_kernel_data_key "${RECOVERY_KERNEL_ALGOID}" "${VERSION}"
  make_pair minios_kernel_data_key "${MINIOS_KERNEL_ALGOID}" "${VERSION}"
  make_pair installer_kernel_data_key "${INSTALLER_KERNEL_ALGOID}" "${VERSION}"

  info "Creating new keyblocks signed with new recovery key."

  make_keyblock recovery_kernel "${RECOVERY_KERNEL_KEYBLOCK_MODE}" recovery_kernel_data_key recovery_key
  make_keyblock minios_kernel "${MINIOS_KERNEL_KEYBLOCK_MODE}" minios_kernel_data_key recovery_key
  make_keyblock installer_kernel "${INSTALLER_KERNEL_KEYBLOCK_MODE}" installer_kernel_data_key recovery_key

  info "Creating secondary XXX.v1.keyblocks signing new kernel data keys with old recovery key."

  make_keyblock recovery_kernel.v1 "${RECOVERY_KERNEL_KEYBLOCK_MODE}" recovery_kernel_data_key recovery_key.v1
  make_keyblock minios_kernel.v1 "${MINIOS_KERNEL_KEYBLOCK_MODE}" minios_kernel_data_key recovery_key.v1
  make_keyblock installer_kernel.v1 "${INSTALLER_KERNEL_KEYBLOCK_MODE}" installer_kernel_data_key recovery_key.v1

  info "All done."
}

main "$@"
