#!/bin/bash -eux
# Copyright 2018 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

me=${0##*/}
TMP="$me.tmp"

# Include /usr/sbin for flahsrom(8)
PATH=/usr/sbin:"${PATH}"

# Test data files
LINK_BIOS="${SCRIPTDIR}/data/bios_link_mp.bin"
PEPPY_BIOS="${SCRIPTDIR}/data/bios_peppy_mp.bin"
LINK_VERSION="Google_Link.2695.1.133"
PEPPY_VERSION="Google_Peppy.4389.89.0"

# Work in scratch directory
cd "$OUTDIR"
set -o pipefail

# Prepare temporary files.
cp -f "${LINK_BIOS}" "${TMP}.emu"

# Test command execution.
versions="$("${FUTILITY}" update -i "${PEPPY_BIOS}" --emulate "${TMP}.emu" |
	    sed -n 's/.*(//; s/).*//p')"
test "${versions}" = \
"RO:${PEPPY_VERSION}, RW/A:${PEPPY_VERSION}, RW/B:${PEPPY_VERSION}
RO:${LINK_VERSION}, RW/A:${LINK_VERSION}, RW/B:${LINK_VERSION}"
