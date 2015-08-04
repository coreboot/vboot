#!/bin/bash
#
# Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set +e

# If tools are not present, do not continue signing
if [ ! type nv_tegrasign ] || [ ! type nv_bct_dump ] || [ ! type nv_cbootimage ]; then
    exit 0
fi

bootloader_length=`nv_bct_dump $2  | grep "Bootloader\[0\]\.Length" | awk '{print$NF}' | cut -d';' -f1`
block_size=`nv_bct_dump $2  | grep "BlockSize" | awk '{print$NF}' | cut -d';' -f1`
start_block=`nv_bct_dump $2  | grep "Bootloader\[0\]\.Start block" | awk '{print$NF}' | cut -d';' -f1`
bootloader_offset=$(($block_size * $start_block))

# Sign bootloader
nv_tegrasign --key $1/nv_pkc.privk --file $2 --offset $bootloader_offset --length $bootloader_length --pubkey pubkey.mod --out bl.sig
cat >update_bl_sig.cfg <<EOF
RsaKeyModulus = pubkey.mod;
RsaPssSigBl = bl.sig;
EOF
nv_cbootimage -s tegra210 -u update_bl_sig.cfg $2 $2-bl-signed

# Sign BCT
bct_offset=`nv_bct_dump $2  | grep "Crypto offset" | awk '{print$NF}' | cut -d';' -f1`
bct_length=`nv_bct_dump $2  | grep "Crypto length" | awk '{print$NF}' | cut -d';' -f1`
nv_tegrasign --key $1/nv_pkc.privk --file $2-bl-signed --offset $bct_offset --length $bct_length --out bct.sig
cat >update_bct_sig.cfg <<EOF
RsaPssSigBct = bct.sig;
EOF
nv_cbootimage -s tegra210 -u update_bct_sig.cfg $2-bl-signed $2-bl-final

cp $2-bl-final $2
exit 0
