#!/bin/bash
# Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Load common constants and variables.
. "$(dirname "$0")/common.sh"

# Where are the programs I'm testing against?
[ -z "${1:-}" ] && error "Directory argument is required"
BINDIR="$1"
shift

OLDDIR="$BINDIR/old_bins"

# create symlinks
for prog in $OLDDIR/*; do
  ln -sf futility "${BINDIR}/${prog##*/}"
done
