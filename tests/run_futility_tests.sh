#!/bin/bash
# Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Load common constants and variables.
. "$(dirname "$0")/common.sh"

# Where are the programs I'm testing against?
BPATH=$(readlink -f $(dirname "$0")/../build)
PATH="${BPATH}/futility:${BPATH}/utility:${BPATH}/cgpt:${PATH}"

echo "PWD is $(pwd)"
# This is the new wrapper program
FUTILITY=futility

# Here are the old programs to be wrapped
# FIXME(chromium-os:37062): There are others besides these.
PROGS=${*:-cgpt crossystem dev_debug_vboot dev_sign_file dumpRSAPublicKey
           dump_fmap dump_kernel_config enable_dev_usb_boot gbb_utility
           tpm_init_temp_fix tpmc vbutil_firmware vbutil_kernel vbutil_key
           vbutil_keyblock vbutil_what_keys}

# Get ready
pass=0
progs=0
OUTDIR="${TEST_DIR}/futility_test_dir"
[ -d "$OUTDIR" ] || mkdir -p "$OUTDIR"

# For now just compare results of invoking each program with no args.
# FIXME(chromium-os:37062): Create true rigorous tests for every program.
for i in $PROGS; do
  : $(( progs++ ))

  # Try the real thing first
  echo -n "$i ... "
  rc=$("$i" 1>"${OUTDIR}/$i.stdout.0" 2>"${OUTDIR}/$i.stderr.0" || echo "$?")
  echo "${rc:-0}" > "${OUTDIR}/$i.return.0"

  # Now try the wrapper version
  rc=$("$FUTILITY" -C "$i" 1>"${OUTDIR}/$i.stdout.1" \
       2>"${OUTDIR}/$i.stderr.1" || echo "$?")
  echo "${rc:-0}" > "${OUTDIR}/$i.return.1"

  # Different?
  if cmp -s "${OUTDIR}/$i.return.0" "${OUTDIR}/$i.return.1" &&
     cmp -s "${OUTDIR}/$i.stdout.0" "${OUTDIR}/$i.stdout.1" &&
     cmp -s "${OUTDIR}/$i.stderr.0" "${OUTDIR}/$i.stderr.1" ; then
    echo -e "${COL_GREEN}passed${COL_STOP}"
    : $(( pass++ ))
    rm -f "${OUTDIR}/$i.*.[01]"
  else
    echo -e "${COL_RED}failed${COL_STOP}"
  fi
done

# done
echo "$pass / $progs passed"
[ "$pass" -eq "$progs" ]
