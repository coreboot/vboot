#!/bin/bash
#
# Copyright 2024 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Tests for swap_ec_rw.

# Load common constants and variables.
. "$(dirname "$0")/common.sh"

set -e

ME=${0##*/}
TMPD="${TEST_DIR}/${ME}"
mkdir -p "${TMPD}"
TMP="${TMPD}/image.bin"

SWAP="${SRCDIR:?}/scripts/image_signing/swap_ec_rw"
DATA="${SRCDIR:?}/tests/swap_ec_rw_data"
KEYSET="${SRCDIR:?}/tests/devkeys"

# Intentionally use AP and EC images from different boards
AP_IMAGE="${DATA}/bios_geralt.bin"
EC_IMAGE="${DATA}/ec_krabby.bin"

LEGACY_EC_IMAGE="${DATA}/ec_boten.bin"
LEGACY_ECRW_IMAGE="${DATA}/ecrw_boten.bin"

echo "Testing swap_ec_rw..."

# Missing -e or --ec
cp -f "${AP_IMAGE}" "${TMP}"
if "${SWAP}" -i "${TMP}" -K "${KEYSET}"; then false; fi

# Good case: swap from EC source (--ec), no ecrw.version
cp -f "${AP_IMAGE}" "${TMP}"
"${SWAP}" -i "${TMP}" -e "${EC_IMAGE}" -K "${KEYSET}"
cmp "${TMP}" "${DATA}/bios.expect.bin"

# Good case: call swap_ec_rw without -K/--keyset (as pack_firmware.py does),
# so swap_ec_rw must find the default keyset itself
cp -f "${AP_IMAGE}" "${TMP}"
"${SWAP}" -i "${TMP}" -e "${EC_IMAGE}"
cmp "${TMP}" "${DATA}/bios.expect.bin"

# Good case: swap from EC source (--ec), with ecrw.version
cp -f "${AP_IMAGE}" "${TMP}"
cbfstool "${TMP}" extract -r "FW_MAIN_A" -n ecrw.version -f "${TMPD}/v.old"
"${SWAP}" -i "${TMP}" -e "${EC_IMAGE}" -K "${KEYSET}"
cbfstool "${TMP}" extract -r "FW_MAIN_A" -n ecrw.version -f "${TMPD}/v.new"
cmp -s "${TMPD}/v.old" "${TMPD}/v.new" && error "ecrw.version was not modified"

# Good case: swap from AP source (--ap_for_ec)
# For testing purposes, AP_IMAGE has different contents between FW_MAIN_A and
# FW_MAIN_B.  Swap the EC and EC config into the source image to create
# a normal AP image.
cp -f "${AP_IMAGE}" "${TMP}.source"
echo "testing config content" > "${TMPD}/ecrw.config"
"${SWAP}" -i "${TMP}.source" -e "${EC_IMAGE}" \
	--ec_config "${TMPD}/ecrw.config" -K "${KEYSET}"
# Swap the ecrw from source image to target image.
cp -f "${AP_IMAGE}" "${TMP}.target"
"${SWAP}" -i "${TMP}.target" -a "${TMP}.source" -K "${KEYSET}"
cmp "${TMP}.target" "${TMP}.source"

# Good case: swap from raw EC RW (--raw_ecrw)
cp -f "${AP_IMAGE}" "${TMP}"
futility dump_fmap -x "${EC_IMAGE}" "EC_RW:${TMPD}/ecrw.bin"
futility dump_fmap -x "${EC_IMAGE}" "RW_FWID:${TMPD}/ecrw.version"
"${SWAP}" -i "${TMP}" -r "${TMPD}/ecrw.bin" -v "${TMPD}/ecrw.version" \
	-K "${KEYSET}"
cmp "${TMP}" "${DATA}/bios.expect.bin"

# Legacy EC which needs to be truncated.
cp -f "${AP_IMAGE}" "${TMP}.1"
cp -f "${AP_IMAGE}" "${TMP}.2"
futility dump_fmap -x "${LEGACY_EC_IMAGE}" "RW_FWID:${TMPD}/legacy_ecrw.version"
"${SWAP}" -i "${TMP}.1" -e "${LEGACY_EC_IMAGE}" -K "${KEYSET}"
"${SWAP}" -i "${TMP}.2" -r "${LEGACY_ECRW_IMAGE}" \
	-v "${TMPD}/legacy_ecrw.version" -K "${KEYSET}"
cmp "${TMP}.1" "${TMP}.2"

# Test swap_cbfs_file with positional CBFS_NAME:FILE arguments
RTK_PDC="${TMPD}/rtk_pdc.bin"
RTK_HASH="${TMPD}/rtk_pdc.hash"
printf "mock-pdc-bin" > "${RTK_PDC}"
printf "\x00\x2c\x03" > "${RTK_HASH}"

cp -f "${AP_IMAGE}" "${TMP}.cbfs"
futility swap_cbfs_file -i "${TMP}.cbfs" -K "${KEYSET}" \
	"rts5453_GOOG0000.bin:${RTK_PDC}" \
	"rts5453_GOOG0000.hash:${RTK_HASH}"

for region in FW_MAIN_A FW_MAIN_B; do
	cbfstool "${TMP}.cbfs" extract -r "${region}" \
		-n rts5453_GOOG0000.bin -f "${TMPD}/rtk.out.bin"
	cbfstool "${TMP}.cbfs" extract -r "${region}" \
		-n rts5453_GOOG0000.hash -f "${TMPD}/rtk.out.hash"
	cmp "${TMPD}/rtk.out.bin" "${RTK_PDC}"
	cmp "${TMPD}/rtk.out.hash" "${RTK_HASH}"
	rm -f "${TMPD}/rtk.out.bin" "${TMPD}/rtk.out.hash"
done

# Test swap_cbfs_file with --pdc using pdctool in PATH
cat > "${TMPD}/pdctool" <<EOF
#!/bin/sh
[ "\$1" = "hash" ] && [ "\$3" = "-o" ] && cp "${RTK_HASH}" "\$4"
EOF
chmod +x "${TMPD}/pdctool"

cp -f "${AP_IMAGE}" "${TMP}.both"
PATH="${TMPD}:${PATH}" "${SWAP}" -i "${TMP}.both" \
	-K "${KEYSET}" \
	-e "${EC_IMAGE}" \
	-p "rts5453_GOOG0000.bin:${RTK_PDC}"
for region in FW_MAIN_A FW_MAIN_B; do
	cbfstool "${TMP}.both" extract -r "${region}" \
		-n rts5453_GOOG0000.bin -f "${TMPD}/rtk.both.bin"
	cmp "${TMPD}/rtk.both.bin" "${RTK_PDC}"
	cbfstool "${TMP}.both" extract -r "${region}" \
		-n rts5453_GOOG0000.hash -f "${TMPD}/rtk.both.hash"
	cmp "${TMPD}/rtk.both.hash" "${RTK_HASH}"
	rm -f "${TMPD}/rtk.both.bin" "${TMPD}/rtk.both.hash"
done

# Cleanup
rm -rf "${TMPD}"
exit 0
