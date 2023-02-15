#!/bin/bash
#
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This script can read GBB flags from system flash or a file.
# This script calls `futility gbb --get`, consider using that directly.

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
  echo 'NOTICE: Please try `futility gbb --get --flash --flags`' 1>&2

  local args=()
  if [ "${FLAGS_explicit}" = "${FLAGS_TRUE}" ]; then
    args+=("--explicit")
  fi

  if [ -n "${FLAGS_file}" ]; then
    args+=("${FLAGS_file}")
  elif [ "${FLAGS_servo}" = "${FLAGS_TRUE}" ]; then
    args+=("--servo")
  else
    args+=("--flash" "--programmer=${FLAGS_programmer}")
  fi

  set -o pipefail # fail if futility fails
  futility gbb --get --flags "${args[@]}" | \
    sed 's/flags: /Chrome OS GBB set flags: /'
}

# Parse command line.
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

main "$@"
