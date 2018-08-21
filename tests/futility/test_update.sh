#!/bin/bash -eux
# Copyright 2018 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

me=${0##*/}
TMP="$me.tmp"

# Test data files
LINK_BIOS="${SCRIPTDIR}/data/bios_link_mp.bin"
LINK_VERSION="Google_Link.2695.1.133"

# Work in scratch directory
cd "$OUTDIR"

set -o pipefail

# Test command execution.

# The updater is now currently always loading system firmware using flashrom(8)
# and can't be tested until an emulation interface is implemented.
