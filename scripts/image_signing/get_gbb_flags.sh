#!/bin/bash
#
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This script can change GBB flags in system live firmware or a given image
# file.

SCRIPT_BASE="$(dirname "$0")"
. "${SCRIPT_BASE}/gbb_flags_common.sh"

# DEFINE_string name default_value description flag
DEFINE_string file "" "Path to firmware image. Default to system firmware." "f"
DEFINE_boolean explicit ${FLAGS_FALSE} "Print list of what flags are set." "e"
DEFINE_string programmer "host" "Programmer to use when setting GBB flags" "p"
DEFINE_boolean servo "${FLAGS_FALSE}"  "Determine programmer using servo" ""

set -e

main() {
  if [ $# -ne 0 ]; then
    flags_help
    exit 1
  fi
  echo 'NOTICE: This script has been replaced with futility functionality and will be removed.' 1>&2
  echo 'NOTICE: Please try `futility gbb --get --flags`' 1>&2

  local image_file="${FLAGS_file}"
  local programmer="${FLAGS_programmer}"

  if [ -z "${FLAGS_file}" ]; then
    image_file="$(make_temp_file)"
    if [ "${FLAGS_servo}" = "${FLAGS_TRUE}" ]; then
      update_programmer_for_servo
    fi
    flashrom_read "${image_file}" "${programmer}"
  fi

  # Process file.

  # Keep 'local' declaration split from assignment so return code is checked.
  local gbb_flags
  gbb_flags="$(futility gbb -g --flags "${image_file}")"
  local raw_gbb_flags="$(echo "${gbb_flags}" | egrep -o "0x[0-9a-fA-F]+")"
  printf "Chrome OS GBB set ${gbb_flags}\n"

  if [ "${FLAGS_explicit}" = "${FLAGS_TRUE}" ]; then
    printf "Chrome OS GBB set flags listed:\n"
    echo "${GBBFLAGS_LIST}" | while read -r flag code; do
      if [ $((code & raw_gbb_flags)) -ne 0 ]; then
        printf "${flag}\n"
      fi
    done
  fi
}

# Parse command line.
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

main "$@"
