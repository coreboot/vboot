#!/bin/bash
# Copyright 2011 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

usage() {
  cat <<EOF
Usage: $PROG <image> [--force]

In-place converts recovery <image> into an SSD image. With --force, does not
ask for confirmation from the user.

EOF
  exit 1
}

if [ $# -lt 1 ] || [ $# -gt 3 ]; then
  usage
else
  IMAGE=$1
  shift
fi

for arg in "$@"; do
  case "$arg" in
  --force)
    IS_FORCE=${arg}
    ;;
  *)
    usage
    ;;
  esac
done

# Load common constants (and use GPT if set above) and variables.
. "$(dirname "$0")/common.sh"

# Abort on errors.
set -e

if [ "${IS_FORCE}" != "--force" ]; then
  echo "This will modify ${IMAGE} in-place and convert it into an SSD image."
  read -p "Are you sure you want to continue (y/N)? " SURE
  SURE="${SURE:0:1}"
  [ "${SURE}" != "y" ] && exit 1
fi

loopdev=$(loopback_partscan "${IMAGE}")
loop_kerna="${loopdev}p2"
loop_kernb="${loopdev}p4"

# Move Kernel B to Kernel A.
info "Replacing Kernel partition A with Kernel partition B"
sudo cp "${loop_kernb}" "${loop_kerna}"

# Zero out Kernel B partition.
info "Zeroing out Kernel partition B"
# This will throw a "disk is full" error, so ignore it.
sudo cp /dev/zero "${loop_kernb}" 2>/dev/null || :

info "${IMAGE} was converted to an SSD image."
