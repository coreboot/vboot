#!/bin/bash
#
# Copyright 2012 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This script can change GBB flags in system flash or a file.
# This script calls `futility gbb --set`, consider using that directly.

SCRIPT_BASE="$(dirname "$0")"
. "${SCRIPT_BASE}/gbb_flags_common.sh"

# DEFINE_string name default_value description flag
DEFINE_string file "" "Path to firmware image. Default to system firmware." "f"
DEFINE_boolean check_wp ${FLAGS_TRUE} "Check write protection states first." ""
DEFINE_string programmer "host" "Programmer to use when setting GBB flags" "p"
DEFINE_boolean servo "${FLAGS_FALSE}"  "Determine programmer using servo" ""

set -e

# Check write protection
# ----------------------------------------------------------------------------
check_write_protection() {
  local hw_wp="" sw_wp=""
  local programmer="$1"
  if [ "${programmer}" = "host" ] && ! crossystem "wpsw_cur?0"; then
    hw_wp="on"
  fi
  # Keep 'local' declaration split from assignment so return code is checked.
  local wp_states
  wp_states="$(flashrom -p "${programmer}" --wp-status 2>/dev/null | grep WP)"
  local wp_disabled="$(echo "${wp_states}" | grep "WP:.*is disabled.")"
  local wp_zero_len="$(echo "${wp_states}" | grep "WP:.*, len=0x00000000")"
  if [ -z "${wp_disabled}" -a -z "${wp_zero_len}" ]; then
    sw_wp="on"
  fi
  if [ -n "${hw_wp}" -a -n "${sw_wp}" ]; then
    return ${FLAGS_FALSE}
  fi
  return ${FLAGS_TRUE}
}

# Main
# ----------------------------------------------------------------------------
main() {
  if [ "$#" != "1" ]; then
    flags_help
    exit 1
  fi
  echo 'NOTICE: This script has been replaced with futility functionality and will be removed.' 1>&2
  echo "NOTICE: Please try \`futility gbb --set --flash --flags=$1\`" 1>&2

  local value="$(($1))"

  local args=()
  if [ -n "${FLAGS_file}" ]; then
    args+=("${FLAGS_file}")
  elif [ "${FLAGS_servo}" = "${FLAGS_TRUE}" ]; then
    args+=("--servo")
  else
    args+=("--flash" "--programmer=${FLAGS_programmer}")
    if [ "${FLAGS_check_wp}" = "${FLAGS_TRUE}" ]; then
      if ! check_write_protection "${FLAGS_programmer}"; then
        echo ""
        echo "WARNING: System GBB Flags are NOT changed!!!"
        echo "ERROR: You must disable write protection before setting flags."
        exit 1
      fi
    fi
  fi

  # Process file
  # Keep 'local' declaration split from assignment so return code is checked.
  local old_value
  old_value="$(futility gbb --get --flags "${args[@]}" | grep "flags: ")"
  printf "Setting GBB flags from %s to %#x\n" "${old_value}" "${value}"
  futility gbb --set --flags="${value}" "${args[@]}"
}

# Parse command line
FLAGS "$@" || exit 1
eval set -- "$FLAGS_ARGV"

main "$@"
