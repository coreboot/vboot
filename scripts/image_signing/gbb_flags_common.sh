#!/bin/sh
#
# Copyright 2017 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This script provides tools to read or change GBB flags on a live system.

SCRIPT_BASE="$(dirname "$0")"
. "${SCRIPT_BASE}/common_minimal.sh"
load_shflags || exit 1

# Globals
# ----------------------------------------------------------------------------

# Values from vboot_reference/firmware/2lib/include/2gbb_flags.h
GBBFLAGS_DESCRIPTION_PREFIX="
  Defined flags (some values may be not supported by all systems):

  "
GBBFLAGS_LIST="
  VB2_GBB_FLAG_DEV_SCREEN_SHORT_DELAY            0x00000001
  VB2_GBB_FLAG_LOAD_OPTION_ROMS                  0x00000002
  VB2_GBB_FLAG_ENABLE_ALTERNATE_OS               0x00000004
  VB2_GBB_FLAG_FORCE_DEV_SWITCH_ON               0x00000008
  VB2_GBB_FLAG_FORCE_DEV_BOOT_USB                0x00000010
  VB2_GBB_FLAG_DISABLE_FW_ROLLBACK_CHECK         0x00000020
  VB2_GBB_FLAG_ENTER_TRIGGERS_TONORM             0x00000040
  VB2_GBB_FLAG_FORCE_DEV_BOOT_ALTFW              0x00000080
  VB2_GBB_FLAG_RUNNING_FAFT                      0x00000100
  VB2_GBB_FLAG_DISABLE_EC_SOFTWARE_SYNC          0x00000200
  VB2_GBB_FLAG_DEFAULT_DEV_BOOT_ALTFW            0x00000400
  VB2_GBB_FLAG_DISABLE_AUXFW_SOFTWARE_SYNC       0x00000800
  VB2_GBB_FLAG_DISABLE_LID_SHUTDOWN              0x00001000
  VB2_GBB_FLAG_FORCE_MANUAL_RECOVERY             0x00004000
  VB2_GBB_FLAG_DISABLE_FWMP                      0x00008000
  VB2_GBB_FLAG_ENABLE_UDC                        0x00010000
  "

GBBFLAGS_DESCRIPTION_SUFFIX="
  To get a developer-friendly device, try 0x11 (short_delay + boot_usb).
  For factory-related tests (always DEV), try 0x39.
  For early development (disable EC/auxfw software sync), try 0xa39.
  "
GBBFLAGS_DESCRIPTION="${GBBFLAGS_DESCRIPTION_PREFIX}${GBBFLAGS_LIST}"
GBBFLAGS_DESCRIPTION="${GBBFLAGS_DESCRIPTION}${GBBFLAGS_DESCRIPTION_SUFFIX}"

FLAGS_HELP="Manages Chrome OS Firmware GBB Flags value.

  Usage: $0 [option_flags] GBB_FLAGS_VALUE
  ${GBBFLAGS_DESCRIPTION}"

flashrom_read() {
  local file="$1"
  local programmer="$2"
  flashrom -p "${programmer}" -i GBB -i FMAP -r "${file}"
}

flashrom_write() {
  local file="$1"
  local programmer="$2"
  flashrom -p "${programmer}"  -i GBB --noverify-all -w "${file}"
}

get_programmer_for_servo() {
  local servo_type
  local serial
  local programmer
  servo_type=$(dut-control -o servo_type 2>/dev/null) || \
    die "Failed to get servo information. Is servod running?"
  case "${servo_type}" in
    *with_servo_micro*)
      serial=$(dut-control -o servo_micro_serialname 2>/dev/null)
      ;;
    *with_c2d2*)
      serial=$(dut-control -o c2d2_serialname 2>/dev/null)
      ;;
    *with_ccd*)
      serial=$(dut-control -o ccd_serialname 2>/dev/null)
      ;;
    *)
      serial=$(dut-control -o serialname 2>/dev/null)
      ;;
  esac
  case "${servo_type}" in
    *servo_micro*|*c2d2*)
      # TODO(sammc): Support servo micro, servo v2 and C2D2. This requires
      # toggling cpu_fw_spi via dut-control before and after running flashrom.
      # C2D2 additionally requires a working cpu_fw_spi implementation.
      die "Unsupported servo type ${servo_type}"
      ;;
    *ccd_cr50*|*ccd_gsc*)
      programmer="raiden_debug_spi:target=AP,serial=${serial}"
      ;;
    *)
      die "Unsupported servo type ${servo_type}"
      ;;
  esac
  echo "${programmer}"
}
