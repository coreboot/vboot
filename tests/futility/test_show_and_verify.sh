#!/bin/bash -eux
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
# Tests for 'futility show' and 'futility verify'.

set -o pipefail

ME="${0##*/}"
TMP="${ME}.tmp"

# Set to 1 to update the expected output
UPDATE_MODE=0

# Test case: <name> <file> <error_level> <extra_options>
#   name: Test case name used to form the expected output file.
#     For example, if name is "abc", then the expected output file will be
#     "tests/futility/expect_output/show.abc".
#   file: Input file.
#   error_level:
#     0: Both 'futility show' and 'futility verify' expected to succeed.
#     1: 'show' expected to succeed, but 'verify' expected to fail.
#     2: Both 'show' and 'verify' expected to fail.
#   extra_options (optional): Extra options passed to 'show' or 'verify'.
TEST_CASES=(
  ## [type] pubkey/prikey
  "root_key.vbpubk tests/devkeys/root_key.vbpubk 0"
  "root_key.vbprivk tests/devkeys/root_key.vbprivk 0"
  "parseable.root_key.vbpubk tests/devkeys/root_key.vbpubk 0 -P"
  "parseable.root_key.vbprivk tests/devkeys/root_key.vbprivk 0 -P"
  ## [type] pubkey21/prikey21 (-P not supported)
  "sample.vbpubk2 tests/futility/data/sample.vbpubk2 0"
  "sample.vbprik2 tests/futility/data/sample.vbprik2 0"
  ## [type] pem (-P not supported)
  "key_rsa2048.pem tests/testkeys/key_rsa2048.pem 0"
  "key_rsa8192.pub.pem tests/testkeys/key_rsa8192.pub.pem 0"
  ## [type] keyblock
  "kernel.keyblock tests/devkeys/kernel.keyblock 1"
  "parseable.kernel.keyblock tests/devkeys/kernel.keyblock 1 -P"
  ## [type] fw_pre
  "fw_vblock tests/futility/data/fw_vblock.bin 1"
  "parseable.fw_vblock tests/futility/data/fw_vblock.bin 1 -P"
  ## [type] gbb
  "gbb tests/futility/data/fw_gbb.bin 0"
  "parseable.gbb tests/futility/data/fw_gbb.bin 0 -P"
  ## [type] bios
  # valid bios without VBOOT_CBFS_INTEGRATION
  "bios_peppy tests/futility/data/bios_peppy_mp.bin 0"
  "parseable.bios_peppy tests/futility/data/bios_peppy_mp.bin 0 -P"
  # bios with VBOOT_CBFS_INTEGRATION; invalid metadata hash in VBLOCK_B
  "bios_coachz_cbfs tests/futility/data/bios_coachz_cbfs.bin 1"
  "parseable.bios_coachz_cbfs tests/futility/data/bios_coachz_cbfs.bin 1 -P"
  # [type] kernel
  "kernel tests/futility/data/kern_preamble.bin 1"
  "parseable.kernel tests/futility/data/kern_preamble.bin 1 -P"
)

for test_case in "${TEST_CASES[@]}"; do
  read -ra arr <<<"${test_case}"
  name="${arr[0]}"
  file="${arr[1]}"
  level="${arr[2]}"
  opts=()
  if [ "${#arr[@]}" -gt 3 ]; then
    opts=("${arr[@]:3}")
  fi

  outfile="show.${name}"
  gotfile="${OUTDIR}/${outfile}"
  wantfile="${SRCDIR}/tests/futility/expect_output/${outfile}"

  succ_cmd=""
  fail_cmd=""
  if [ "${level}" -eq 0 ]; then
    succ_cmd="verify"
  elif [ "${level}" -eq 1 ]; then
    succ_cmd="show"
    fail_cmd="verify"
  else
    fail_cmd="show"
  fi

  if [ -n "${succ_cmd}" ]; then
    ( cd "${SRCDIR}" && "${FUTILITY}" "${succ_cmd}" "${file}" "${opts[@]}" ) \
      | tee "${gotfile}"

    [[ "${UPDATE_MODE}" -gt 0 ]] && cp "${gotfile}" "${wantfile}"
    diff "${wantfile}" "${gotfile}"
  fi

  if [ -n "${fail_cmd}" ]; then
    ( cd "${SRCDIR}" && ! "${FUTILITY}" "${fail_cmd}" "${file}" "${opts[@]}" ) \
      || ( echo "Command expected to fail, but succeeded" && false )
  fi
done

# cleanup
rm -rf "${TMP}"*
exit 0
