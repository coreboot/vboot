#!/bin/bash -eux
# Copyright 2018 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

me=${0##*/}
TMP="$me.tmp"

# Test --sys_props (primitive test needed for future updating tests).
test_sys_props() {
	! "${FUTILITY}" --debug update --sys_props "$*" |
		sed -n 's/.*property\[\(.*\)].value = \(.*\)/\1,\2,/p' |
		tr '\n' ' '
}

test "$(test_sys_props "1,2,3")" = "0,1, 1,2, 2,3, "
test "$(test_sys_props "1 2 3")" = "0,1, 1,2, 2,3, "
test "$(test_sys_props "1, 2,3 ")" = "0,1, 1,2, 2,3, "
test "$(test_sys_props "   1,, 2")" = "0,1, 2,2, "
test "$(test_sys_props " , 4,")" = "1,4, "

# Test data files
LINK_BIOS="${SCRIPTDIR}/data/bios_link_mp.bin"
PEPPY_BIOS="${SCRIPTDIR}/data/bios_peppy_mp.bin"

# Work in scratch directory
cd "$OUTDIR"
set -o pipefail

# In all the test scenario, we want to test "updating from PEPPY to LINK".
TO_IMAGE=${TMP}.src.link
FROM_IMAGE=${TMP}.src.peppy
TO_HWID="X86 LINK TEST 6638"
FROM_HWID="X86 PEPPY TEST 4211"
cp -f ${LINK_BIOS} ${TO_IMAGE}
cp -f ${PEPPY_BIOS} ${FROM_IMAGE}

unpack_image() {
	local folder="${TMP}.$1"
	local image="$2"
	mkdir -p "${folder}"
	(cd "${folder}" && ${FUTILITY} dump_fmap -x "../${image}")
}

# Unpack images so we can prepare expected results by individual sections.
unpack_image "to" "${TO_IMAGE}"
unpack_image "from" "${FROM_IMAGE}"

# Generate expected results.
cp -f "${TO_IMAGE}" "${TMP}.expected.full"
cp -f "${FROM_IMAGE}" "${TMP}.expected.rw"
cp -f "${FROM_IMAGE}" "${TMP}.expected.a"
cp -f "${FROM_IMAGE}" "${TMP}.expected.b"
"${FUTILITY}" gbb -s --hwid="${FROM_HWID}" "${TMP}.expected.full"
"${FUTILITY}" load_fmap "${TMP}.expected.full" \
	RW_VPD:${TMP}.from/RW_VPD \
	RO_VPD:${TMP}.from/RO_VPD
"${FUTILITY}" load_fmap "${TMP}.expected.rw" \
	RW_SECTION_A:${TMP}.to/RW_SECTION_A \
	RW_SECTION_B:${TMP}.to/RW_SECTION_B \
	RW_SHARED:${TMP}.to/RW_SHARED \
	RW_LEGACY:${TMP}.to/RW_LEGACY
"${FUTILITY}" load_fmap "${TMP}.expected.a" \
	RW_SECTION_A:${TMP}.to/RW_SECTION_A
"${FUTILITY}" load_fmap "${TMP}.expected.b" \
	RW_SECTION_B:${TMP}.to/RW_SECTION_B

test_update() {
	local test_name="$1"
	local emu_src="$2"
	local expected="$3"
	local error_msg="${expected#!}"
	local msg

	shift 3
	cp -f "${emu_src}" "${TMP}.emu"
	echo "*** Test Item: ${test_name}"
	"${FUTILITY}" update --emulate "${TMP}.emu" "$@"
	cmp "${TMP}.emu" "${expected}"
}

# --sys_props: mainfw_act, [wp_hw, wp_sw]

# Test Full update.
test_update "Full update" \
	"${FROM_IMAGE}" "${TMP}.expected.full" \
	-i "${TO_IMAGE}" --wp=0

# Test RW-only update.
test_update "RW update" \
	"${FROM_IMAGE}" "${TMP}.expected.rw" \
	-i "${TO_IMAGE}" --wp=1

# Test Try-RW update (vboot2).
test_update "RW update (A->B)" \
	"${FROM_IMAGE}" "${TMP}.expected.b" \
	-i "${TO_IMAGE}" -t --wp=1 --sys_props 0

test_update "RW update (B->A)" \
	"${FROM_IMAGE}" "${TMP}.expected.a" \
	-i "${TO_IMAGE}" -t --wp=1 --sys_props 1

test_update "RW update -> fallback to RO+RW Full update" \
	"${FROM_IMAGE}" "${TMP}.expected.full" \
	-i "${TO_IMAGE}" -t --wp=0 --sys_props 1
