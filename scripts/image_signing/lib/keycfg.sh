#!/bin/bash

# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Setup the default key configuration by using the local key in `key_dir`.
setup_default_keycfg() {
  local key_dir=$1
  export KEYCFG_KERNEL_KEYBLOCK="${key_dir}/kernel.keyblock"
  export KEYCFG_KERNEL_VBPRIVK="${key_dir}/kernel_data_key.vbprivk"
  export KEYCFG_MINIOS_KERNEL_KEYBLOCK="${key_dir}/minios_kernel.keyblock"
  export KEYCFG_MINIOS_KERNEL_V1_KEYBLOCK="${key_dir}/minios_kernel.v1.keyblock"
  export KEYCFG_MINIOS_KERNEL_VBPRIVK="${key_dir}/minios_kernel_data_key.vbprivk"
  export KEYCFG_RECOVERY_KERNEL_KEYBLOCK="${key_dir}/recovery_kernel.keyblock"
  export KEYCFG_RECOVERY_KERNEL_V1_KEYBLOCK="${key_dir}/recovery_kernel.v1.keyblock"
  export KEYCFG_RECOVERY_KERNEL_VBPRIVK="${key_dir}/recovery_kernel_data_key.vbprivk"
  export KEYCFG_INSTALLER_KERNEL_KEYBLOCK="${key_dir}/installer_kernel.keyblock"
  export KEYCFG_INSTALLER_KERNEL_V1_KEYBLOCK="${key_dir}/installer_kernel.v1.keyblock"
  export KEYCFG_INSTALLER_KERNEL_VBPRIVK="${key_dir}/installer_kernel_data_key.vbprivk"
  export KEYCFG_ARV_PLATFORM_KEYBLOCK="${key_dir}/arv_platform.keyblock"
  export KEYCFG_ARV_PLATFORM_VBPRIVK="${key_dir}/arv_platform.vbprivk"
  export KEYCFG_UEFI_PRIVATE_KEY="${key_dir}/uefi/db/db.children/db_child.rsa"
  export KEYCFG_UEFI_SIGN_CERT="${key_dir}/uefi/db/db.children/db_child.pem"
  export KEYCFG_UEFI_VERIFY_CERT="${key_dir}/uefi/db/db.pem"
  export KEYCFG_KEY_EC_EFS_VBPRIK2="${key_dir}/key_ec_efs.vbprik2"
  # This is for `sign_official_build.sh accessory_rwsig`, which uses arbitrary
  # one of .vbprik2 in KEY_DIR if KEYCFG_ACCESSORY_RWSIG_VBPRIK2 is empty or unset.
  export KEYCFG_ACCESSORY_RWSIG_VBPRIK2=""

  export KEYCFG_ROOT_KEY_VBPUBK="${key_dir}/root_key.vbpubk"
  declare -a KEYCFG_ROOT_KEY_VBPUBK_LOEM
  export KEYCFG_FIRMWARE_VBPRIVK="${key_dir}/firmware_data_key.vbprivk"
  declare -a KEYCFG_FIRMARE_VBPRIVK_LOEM
  export KEYCFG_FIRMWARE_KEYBLOCK="${key_dir}/firmware.keyblock"
  declare -a KEYCFG_FIRMARE_KEYBLOCK_LOEM
}

# Setup the key configuration. This setups the default configuration and source
# the key_config.sh in `key_dir` to overwrite the default value.
setup_keycfg() {
  local key_dir=$1
  setup_default_keycfg "${key_dir}"
  export KEYCFG_KEY_DIR="${key_dir}"
  if [ -f "${key_dir}/key_config.sh" ]; then
    . "${key_dir}/key_config.sh"
  fi
}

# Check if KEYCFG_KEY_DIR is set properly.
check_key_dir() {
  if [[ -z "${KEYCFG_KEY_DIR}" ]]; then
    echo "KEYCFG_KEY_DIR is unset. Try run setup_keycfg first." >&2
    exit 1
  fi
  if [[ ! -d "${KEYCFG_KEY_DIR}" ]]; then
    echo "The key directory '${KEYCFG_KEY_DIR}' doesn't exist." >&2
    exit 1
  fi
}

# Get the default or configured path of root key with loem suffix. It could be
# either local or PKCS#11 path. If LOEM_INDEX is not specified, the non-loem
# root key would be returned.
# Args: [LOEM_INDEX]
get_root_key_vbpubk() {
  local loem_index=$1
  check_key_dir
  if [[ -z "${loem_index}" ]]; then
    echo "${KEYCFG_ROOT_KEY_VBPUBK}"
    return
  fi
  local default="${KEYCFG_KEY_DIR}/root_key.loem${loem_index}.vbpubk"
  echo "${KEYCFG_ROOT_KEY_VBPUBK_LOEM[${loem_index}]:-${default}}"
}

# Get the default or configured path of firmware data key with loem suffix. It
# could be either local or PKCS#11 path. If LOEM_INDEX is not specified, the
# non-loem data key would be returned.
# Args: [LOEM_INDEX]
get_firmware_vbprivk() {
  local loem_index=$1
  check_key_dir
  if [[ -z "${loem_index}" ]]; then
    echo "${KEYCFG_FIRMWARE_VBPRIVK}"
    return
  fi
  local default="${KEYCFG_KEY_DIR}/firmware_data_key.loem${loem_index}.vbprivk"
  echo "${KEYCFG_FIRMARE_VBPRIVK_LOEM[${loem_index}]:-${default}}"
}

# Get the default or configured path of firmware key block with loem suffix. It
# could be either local or PKCS#11 path. If LOEM_INDEX is not specified, the
# non-loem key block would be returned.
# Args: [LOEM_INDEX]
get_firmware_keyblock() {
  local loem_index=$1
  check_key_dir
  if [[ -z "${loem_index}" ]]; then
    echo "${KEYCFG_FIRMWARE_KEYBLOCK}"
    return
  fi
  local default="${KEYCFG_KEY_DIR}/firmware.loem${loem_index}.keyblock"
  echo "${KEYCFG_FIRMARE_KEYBLOCK_LOEM[${loem_index}]:-${default}}"
}
