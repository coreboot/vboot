#!/bin/bash -eux
# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

me=${0##*/}
TMP="$me.tmp"

# Work in scratch directory
cd "$OUTDIR"


IN="${SCRIPT_DIR}/futility/data/bios_link_mp.bin"
BIOS="${TMP}.bios.bin"

cp "${IN}" "${BIOS}"

AREAS=(RW_SECTION_A VBLOCK_B BOOT_STUB)
set -x
# Extract good blobs first
"${FUTILITY}" dump_fmap -x "${BIOS}" "${AREAS[@]}"

# Save the good blobs, make same-size random blobs, create command
CMDS=( )
for a in "${AREAS[@]}"; do
  size=$(stat -c '%s' "$a")
  mv "$a" "$a.good"
  dd if=/dev/urandom of="$a.rand" bs="$size" count=1
  CMDS+=("$a:$a.rand")
done

# Poke the new blobs in
"${FUTILITY}" load_fmap "${BIOS}" "${CMDS[@]}"

# Pull them back out and see if they match
"${FUTILITY}" dump_fmap -x "${BIOS}" "${AREAS[@]}"
for a in "${AREAS[@]}"; do
  cmp "$a" "$a.rand"
done

# File size smaller than area size
cp -f "${IN}" "${BIOS}"
"${FUTILITY}" dump_fmap -x "${BIOS}" VBLOCK_A
cp -f VBLOCK_A VBLOCK_A.truncated
truncate --size=-5 VBLOCK_A.truncated
cp -f VBLOCK_A.truncated VBLOCK_A.new
printf '\xFF%.s' {1..5} >> VBLOCK_A.new
cmp -s VBLOCK_A.new VBLOCK_A && error "VBLOCK_A.new is the same as VBLOCK_A"
"${FUTILITY}" load_fmap "${BIOS}" VBLOCK_A:VBLOCK_A.truncated
"${FUTILITY}" dump_fmap -x "${BIOS}" VBLOCK_A:VBLOCK_A.readback
cmp VBLOCK_A.readback VBLOCK_A.new

# cleanup
rm -f "${TMP}"* "${AREAS[@]}" ./*.rand ./*.good
exit 0
