#!/bin/bash
# Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Fail on any unexpected nonsense.
set -e -u

# The one required argument is the directory where futility lives.
BINDIR="$1"
shift

# We look here to see what names to use for the symlinks.
OLDDIR="$BINDIR/old_bins"

# Create the symlinks.
for prog in $OLDDIR/*; do
  ln -sf futility "${BINDIR}/${prog##*/}"
done
