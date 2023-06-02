#!/bin/bash -eux
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

me=${0##*/}
TMP="${me}.tmp"

# Work in scratch directory
cd "${OUTDIR}"

# Test good VPD
TEST_VPD_GOOD="${SCRIPT_DIR}/futility/data/vpd_good.bin"
"${FUTILITY}" vpd "${TEST_VPD_GOOD}" > "${TMP}"
cmp "${SCRIPT_DIR}/futility/data_vpd_good_expect.txt" "${TMP}"

# Test empty VPD
TEST_VPD_EMPTY="${SCRIPT_DIR}/futility/data/vpd_empty.bin"
"${FUTILITY}" vpd "${TEST_VPD_EMPTY}" > "${TMP}"
if [ -s "${TMP}" ]; then false; fi

# Test bad format
TEST_VPD_BAD="${SCRIPT_DIR}/futility/data/vpd_bad.bin"
if "${FUTILITY}" vpd "{TEST_VPD_BAD}" > "${TMP}"; then false; fi

# Cleanup
rm -f "${TMP}"*
exit 0
