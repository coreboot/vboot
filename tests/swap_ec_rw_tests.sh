#!/bin/bash
#
# Copyright 2024 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Tests for swap_ec_rw.

# Load common constants and variables.
. "$(dirname "$0")/common.sh"

set -e

ME=${0##*/}
TMPD="${TEST_DIR}/${ME}"
mkdir -p "${TMPD}"
TMP="${TMPD}/image.bin"

SWAP="${SRCDIR:?}/scripts/image_signing/swap_ec_rw"
DATA="${SRCDIR:?}/tests/swap_ec_rw_data"

# Intentionally use AP and EC images from different boards
AP_IMAGE="${DATA}/bios_geralt.bin"
EC_IMAGE="${DATA}/ec_krabby.bin"
EC_RW_FWID="${DATA}/RW_FWID"

echo "Testing swap_ec_rw..."

# Missing -e or --ec
cp -f "${AP_IMAGE}" "${TMP}"
if "${SWAP}" -i "${TMP}"; then false; fi

# Good case: no ecrw.version
cp -f "${AP_IMAGE}" "${TMP}"
"${SWAP}" -i "${TMP}" -e "${EC_IMAGE}"
cmp "${TMP}" "${DATA}/bios.expect.bin"

# Good case: swap ecrw.version
cp -f "${AP_IMAGE}" "${TMP}"
cbfstool "${TMP}" add -r "FW_MAIN_A,FW_MAIN_B" -t raw \
  -c none -f "${EC_RW_FWID}" -n ecrw.version
"${SWAP}" -i "${TMP}" -e "${EC_IMAGE}"
cbfstool "${TMP}" extract -r "FW_MAIN_A" -n ecrw.version -f "${TMPD}/v"
cmp -s "${TMPD}/v" "${EC_RW_FWID}" && error "ecrw.version was not modified"

# Cleanup
rm -rf "${TMPD}"
exit 0
