#!/bin/bash
#
# Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set +e

# If tools are not present, do not continue signing
if [ ! type nv_bct_dump ] || [ ! type nv_cbootimage ]; then
    exit 0
fi

cat >update.cfg <<EOF
PkcKey = $1/nv_pkc.pem;
ReSignBl;
EOF

nv_cbootimage -s tegra210 -u update.cfg $2 $2-final
cp $2-final $2

exit 0
