#!/bin/bash

# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Load common constants and functions.
. "$(dirname "$0")/../common.sh"

usage() {
  cat <<EOF
Usage: ${PROG} [options]

Options:
  -o, --output_dir <dir>:    Where to write the keys (default is cwd)
EOF

  if [[ $# -ne 0 ]]; then
    die "$*"
  else
    exit 0
  fi
}

generate_ed25519_key() {
  local output_dir="$1"

  # Generate ed25519 private and public key.
  openssl genpkey -algorithm Ed25519 -out "${output_dir}/key_hps.priv.pem"
  openssl pkey -in "${output_dir}/key_hps.priv.pem" -pubout -text_pub \
    -out "${output_dir}/key_hps.pub.pem"
}

main() {
  set -euo pipefail

  local output_dir="${PWD}"

  while [[ $# -gt 0 ]]; do
    case "$1" in
    -h|--help)
      usage
      ;;
    -o|--output_dir)
      output_dir="$2"
      if [[ ! -d "${output_dir}" ]]; then
        die "output dir (${output_dir}) doesn't exist."
      fi
      shift
      ;;
    -*)
      usage "Unknown option: $1"
      ;;
    *)
      usage "Unknown argument $1"
      ;;
    esac
    shift
  done

  generate_ed25519_key "${output_dir}"
}

main "$@"
