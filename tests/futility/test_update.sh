#!/bin/bash -eux
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

me=${0##*/}
TMP="$me.tmp"

# Test --sys_props (primitive test needed for future updating tests).
test_sys_props() {
  ! "${FUTILITY}" --debug update --sys_props "$*" 2>&1 |
    sed -n 's/.*property\[\(.*\)].value = \(.*\)/\1,\2,/p' |
    tr '\n' ' '
}

test "$(test_sys_props "1,2,3")" = "0,1, 1,2, 2,3, "
test "$(test_sys_props "1 2 3")" = "0,1, 1,2, 2,3, "
test "$(test_sys_props "1, 2,3 ")" = "0,1, 1,2, 2,3, "
test "$(test_sys_props "   1,, 2")" = "0,1, 2,2, "
test "$(test_sys_props " , 4,")" = "1,4, "

test_quirks() {
  ! "${FUTILITY}" --debug update --quirks "$*" 2>&1 |
    sed -n 's/.*Set quirk \(.*\) to \(.*\)./\1,\2/p' |
    tr '\n' ' '
}

test "$(test_quirks "enlarge_image")" = "enlarge_image,1 "
test "$(test_quirks "enlarge_image=2")" = "enlarge_image,2 "
test "$(test_quirks " enlarge_image, enlarge_image=2")" = \
  "enlarge_image,1 enlarge_image,2 "

# Test data files
DATA_DIR="${SCRIPT_DIR}/futility/data"
GERALT_BIOS="${DATA_DIR}/bios_geralt_cbfs.bin"
LINK_BIOS="${DATA_DIR}/bios_link_mp.bin"
PEPPY_BIOS="${DATA_DIR}/bios_peppy_mp.bin"
VOXEL_BIOS="${DATA_DIR}/bios_voxel_dev.bin"
RO_VPD_BLOB="${DATA_DIR}/ro_vpd.bin"
SIGNER_CONFIG="${DATA_DIR}/signer_config.csv"

# Work in scratch directory
cd "$OUTDIR"
set -o pipefail

# In all the test scenario, we want to test "updating from PEPPY to LINK".
TO_IMAGE="${TMP}.src.link"
FROM_IMAGE="${TMP}.src.peppy"
TO_HWID="X86 LINK TEST 6638"
FROM_HWID="X86 PEPPY TEST 4211"
cp -f "${LINK_BIOS}" "${TO_IMAGE}"
cp -f "${PEPPY_BIOS}" "${FROM_IMAGE}"
"${FUTILITY}" load_fmap "${FROM_IMAGE}" \
  RO_VPD:"${RO_VPD_BLOB}" RW_VPD:"${RO_VPD_BLOB}"
cp -f "${FROM_IMAGE}" "${FROM_IMAGE}".unpatched

patch_file() {
  local file="$1"
  local section="$2"
  local section_offset="$3"
  local data="$4"

  # NAME OFFSET SIZE
  local fmap_info
  local base
  local offset

  fmap_info="$("${FUTILITY}" dump_fmap -p "${file}" "${section}")"
  base="$(echo "${fmap_info}" | sed 's/^[^ ]* //; s/ [^ ]*$//')"
  offset=$((base + section_offset))
  echo "offset: ${offset}"
  printf "%b" "${data}" | dd of="${file}" bs=1 seek="${offset}" \
    conv=notrunc
}

# PEPPY and LINK have different platform element ("Google_Link" and
# "Google_Peppy") in firmware ID so we want to hack them by changing
# "Google_" to "Google.".
patch_file "${TO_IMAGE}" RW_FWID_A 0 Google.
patch_file "${TO_IMAGE}" RW_FWID_B 0 Google.
patch_file "${TO_IMAGE}" RO_FRID 0 Google.
patch_file "${FROM_IMAGE}" RW_FWID_A 0 Google.
patch_file "${FROM_IMAGE}" RW_FWID_B 0 Google.
patch_file "${FROM_IMAGE}" RO_FRID 0 Google.

unpack_image() {
  local folder="${TMP}.$1"
  local image="$2"
  mkdir -p "${folder}"
  (cd "${folder}" && "${FUTILITY}" dump_fmap -x "../${image}")
  "${FUTILITY}" gbb -g --rootkey="${folder}/rootkey" "${image}"
}

# Unpack images so we can prepare expected results by individual sections.
unpack_image "to" "${TO_IMAGE}"
unpack_image "from" "${FROM_IMAGE}"

# Hack FROM_IMAGE so it has same root key as TO_IMAGE (for RW update).
FROM_DIFFERENT_ROOTKEY_IMAGE="${FROM_IMAGE}2"
cp -f "${FROM_IMAGE}" "${FROM_DIFFERENT_ROOTKEY_IMAGE}"
"${FUTILITY}" gbb -s --rootkey="${TMP}.to/rootkey" "${FROM_IMAGE}"

# Hack for quirks
cp -f "${FROM_IMAGE}" "${FROM_IMAGE}.large"
truncate -s $((8388608 * 2)) "${FROM_IMAGE}.large"

# Create the FROM_SAME_RO_IMAGE using the RO from TO_IMAGE."
FROM_SAME_RO_IMAGE="${FROM_IMAGE}.same_ro"
cp -f "${FROM_IMAGE}" "${FROM_SAME_RO_IMAGE}"
"${FUTILITY}" load_fmap "${FROM_SAME_RO_IMAGE}" \
  "RO_SECTION:${TMP}.to/RO_SECTION"

# Create GBB v1.2 images (for checking digest)
GBB_OUTPUT="$("${FUTILITY}" gbb --digest "${TO_IMAGE}")"
[ "${GBB_OUTPUT}" = "digest: <none>" ]
TO_IMAGE_GBB12="${TO_IMAGE}.gbb12"
HWID_DIGEST="adf64d2a434b610506153da42440b0b498d7369c0e98b629ede65eb59f4784fa"
cp -f "${TO_IMAGE}" "${TO_IMAGE_GBB12}"
patch_file "${TO_IMAGE_GBB12}" GBB 6 "\x02"
"${FUTILITY}" gbb -s --hwid="${TO_HWID}" "${TO_IMAGE_GBB12}"
GBB_OUTPUT="$("${FUTILITY}" gbb --digest "${TO_IMAGE_GBB12}")"
[ "${GBB_OUTPUT}" = "digest: ${HWID_DIGEST}   valid" ]

# Create images with (empty) AP RO verification
# (Patch FMAP to rename 'RO_UNUSED' to 'RO_GSCVD')
cp -f "${FROM_IMAGE}" "${FROM_IMAGE}.locked"
patch_file "${FROM_IMAGE}.locked" FMAP 0x0430 "RO_GSCVD\x00"
cp -f "${FROM_IMAGE}.locked" "${FROM_IMAGE}.locked_same_desc"
cp -f "${FROM_IMAGE}.locked" "${FROM_IMAGE}.unlocked"
patch_file "${FROM_IMAGE}.unlocked" SI_DESC 0x60 \
  "\x00\xff\xff\xff\x00\xff\xff\xff\x00\xff\xff\xff"
"${FUTILITY}" load_fmap "${FROM_IMAGE}.locked_same_desc" \
  "SI_DESC:${TMP}.to/SI_DESC"

# Generate expected results.
cp -f "${TO_IMAGE}" "${TMP}.expected.full"
cp -f "${FROM_IMAGE}" "${TMP}.expected.rw"
cp -f "${FROM_IMAGE}" "${TMP}.expected.a"
cp -f "${FROM_IMAGE}" "${TMP}.expected.b"
cp -f "${FROM_SAME_RO_IMAGE}" "${TMP}.FROM_SAME_RO_IMAGE.expected.b"
cp -f "${FROM_IMAGE}" "${TMP}.expected.legacy"
"${FUTILITY}" gbb -s --hwid="${FROM_HWID}" "${TMP}.expected.full"
"${FUTILITY}" load_fmap "${TMP}.expected.full" \
  "RW_VPD:${TMP}.from/RW_VPD" \
  "RO_VPD:${TMP}.from/RO_VPD"
"${FUTILITY}" load_fmap "${TMP}.expected.rw" \
  "RW_SECTION_A:${TMP}.to/RW_SECTION_A" \
  "RW_SECTION_B:${TMP}.to/RW_SECTION_B" \
  "RW_SHARED:${TMP}.to/RW_SHARED" \
  "RW_LEGACY:${TMP}.to/RW_LEGACY"
"${FUTILITY}" load_fmap "${TMP}.expected.a" \
  "RW_SECTION_A:${TMP}.to/RW_SECTION_A"
"${FUTILITY}" load_fmap "${TMP}.expected.b" \
  "RW_SECTION_B:${TMP}.to/RW_SECTION_B"
"${FUTILITY}" load_fmap "${TMP}.FROM_SAME_RO_IMAGE.expected.b" \
  "RW_SECTION_B:${TMP}.to/RW_SECTION_B"
"${FUTILITY}" load_fmap "${TMP}.expected.legacy" \
  "RW_LEGACY:${TMP}.to/RW_LEGACY"
cp -f "${TMP}.expected.full" "${TMP}.expected.full.gbb12"
patch_file "${TMP}.expected.full.gbb12" GBB 6 "\x02"
"${FUTILITY}" gbb -s --hwid="${FROM_HWID}" "${TMP}.expected.full.gbb12"
cp -f "${TMP}.expected.full" "${TMP}.expected.full.gbb0"
"${FUTILITY}" gbb -s --flags=0 "${TMP}.expected.full.gbb0"
cp -f "${FROM_IMAGE}" "${FROM_IMAGE}.gbb0"
"${FUTILITY}" gbb -s --flags=0 "${FROM_IMAGE}.gbb0"
cp -f "${TMP}.expected.full" "${TMP}.expected.full.gbb0x27"
"${FUTILITY}" gbb -s --flags=0x27 "${TMP}.expected.full.gbb0x27"
cp -f "${TMP}.expected.full" "${TMP}.expected.large"
dd if=/dev/zero bs=8388608 count=1 | tr '\000' '\377' >>"${TMP}.expected.large"
cp -f "${TMP}.expected.full" "${TMP}.expected.me_unlocked_eve"
patch_file "${TMP}.expected.me_unlocked_eve" SI_DESC 0x60 \
  "\x00\xff\xff\xff\x00\xff\xff\xff\x00\xff\xff\xff"
cp -f "${TMP}.expected.full" "${TMP}.expected.me_preserved"
"${FUTILITY}" load_fmap "${TMP}.expected.me_preserved" \
  "SI_ME:${TMP}.from/SI_ME"
cp -f "${TMP}.expected.rw" "${TMP}.expected.rw.locked"
patch_file "${TMP}.expected.rw.locked" FMAP 0x0430 "RO_GSCVD\x00"

# A special set of images that only RO_VPD is preserved (RW_VPD is wiped) using
# FMAP_AREA_PRESERVE (\010=0x08).
TO_IMAGE_WIPE_RW_VPD="${TO_IMAGE}.wipe_rw_vpd"
cp -f "${TO_IMAGE}" "${TO_IMAGE_WIPE_RW_VPD}"
patch_file "${TO_IMAGE_WIPE_RW_VPD}" FMAP 0x3fc "$(printf '\010')"
cp -f "${TMP}.expected.full" "${TMP}.expected.full.empty_rw_vpd"
"${FUTILITY}" load_fmap "${TMP}.expected.full.empty_rw_vpd" \
  RW_VPD:"${TMP}.to/RW_VPD"
patch_file "${TMP}.expected.full.empty_rw_vpd" FMAP 0x3fc "$(printf '\010')"

# Generate images for testing --unlock_me.
# There are two ways to detect the platform:
#  - Read CONFIG_IFD_CHIPSET from config file in CBFS
#  - Fallback for nissa: check if CONFIG_IFD_BIN_PATH contains 'nissa'

# Rename BOOT_STUB to COREBOOT, which is the default region used by cbfstool.
rename_boot_stub() {
  local image="$1"

  "${FUTILITY}" dump_fmap "${image}" -x "FMAP:${TMP}.fmap"
  sed -i 's/BOOT_STUB/COREBOOT\x00/g' "${TMP}.fmap"
  "${FUTILITY}" load_fmap "${image}" "FMAP:${TMP}.fmap"
}

# Add the given line to the config file in CBFS.
add_config() {
  local image="$1"
  local config_line="$2"

  rename_boot_stub "${image}"

  cbfstool "${image}" extract -n config -f "${TMP}.config"
  echo "${config_line}" >> "${TMP}.config"
  cbfstool "${image}" remove -n config
  cbfstool "${image}" add -n config -f "${TMP}.config" -t raw
}

unlock_me() {
  local image="$1"

  patch_file "${image}" SI_DESC 0x60 \
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
  patch_file "${image}" SI_DESC 0x154 \
    "\x00\x00\x00\x00"
}

IFD_CHIPSET="CONFIG_IFD_CHIPSET=\"adl\""
IFD_PATH="CONFIG_IFD_BIN_PATH=\"3rdparty/blobs/mainboard/google/nissa/descriptor-craask.bin\""
cp -f "${TO_IMAGE}" "${TO_IMAGE}.ifd_chipset"
cp -f "${TO_IMAGE}" "${TO_IMAGE}.ifd_path"
cp -f "${TMP}.expected.full" "${TMP}.expected.ifd_chipset"
cp -f "${TMP}.expected.full" "${TMP}.expected.ifd_path"
add_config "${TO_IMAGE}.ifd_chipset" "${IFD_CHIPSET}"
add_config "${TO_IMAGE}.ifd_path" "${IFD_PATH}"
add_config "${TMP}.expected.ifd_chipset" "${IFD_CHIPSET}"
add_config "${TMP}.expected.ifd_path" "${IFD_PATH}"

cp -f "${TMP}.expected.ifd_chipset" "${TMP}.expected.me_unlocked.ifd_chipset"
cp -f "${TMP}.expected.ifd_path" "${TMP}.expected.me_unlocked.ifd_path"
unlock_me "${TMP}.expected.me_unlocked.ifd_chipset"
unlock_me "${TMP}.expected.me_unlocked.ifd_path"

# Has 3 modes:
# 1. $3 = "!something", run command, expect failure,
#    grep for something in log, fail if it is not present
# 2. $3 = "something", run command, expect success,
#    cmp output to file named $3, fail if they are not the same
# 3. $3 = "!", run command, expect success, fail to find a file named !
test_update() {
  local test_name="$1"
  local emu_src="$2"
  local expected="$3"
  local error_msg="${expected#!}"
  local msg

  shift 3
  cp -f "${emu_src}" "${TMP}.emu"
  echo "*** Test Item: ${test_name}"
  if [ "${error_msg}" != "${expected}" ] && [ -n "${error_msg}" ]; then
    msg="$(! "${FUTILITY}" update --emulate "${TMP}.emu" "$@" 2>&1)"
    grep -qF -- "${error_msg}" <<<"${msg}"
  else
    "${FUTILITY}" update --emulate "${TMP}.emu" "$@"
    cmp "${TMP}.emu" "${expected}"
  fi
}

# --sys_props: mainfw_act, tpm_fwver, platform_ver, [wp_hw, wp_sw]
# tpm_fwver = <data key version:16><firmware version:16>.
# TO_IMAGE is signed with data key version = 1, firmware version = 4 => 0x10004.

# Test Full update.
test_update "Full update" \
  "${FROM_IMAGE}" "${TMP}.expected.full" \
  -i "${TO_IMAGE}" --wp=0

test_update "Full update (incompatible platform)" \
  "${FROM_IMAGE}" "!platform is not compatible" \
  -i "${LINK_BIOS}" --wp=0

test_update "Full update (TPM Anti-rollback: data key)" \
  "${FROM_IMAGE}" "!Data key version rollback detected (2->1)" \
  -i "${TO_IMAGE}" --wp=0 --sys_props 1,0x20001

test_update "Full update (TPM Anti-rollback: kernel key)" \
  "${FROM_IMAGE}" "!Firmware version rollback detected (5->4)" \
  -i "${TO_IMAGE}" --wp=0 --sys_props 1,0x10005

test_update "Full update (TPM Anti-rollback: 0 as tpm_fwver)" \
  "${FROM_IMAGE}" "${TMP}.expected.full" \
  -i "${TO_IMAGE}" --wp=0 --sys_props ,0x0

test_update "Full update (TPM check failure due to invalid tpm_fwver)" \
  "${FROM_IMAGE}" "!Invalid tpm_fwver: -1" \
  -i "${TO_IMAGE}" --wp=0 --sys_props ,-1

test_update "Full update (Skip TPM check with --force)" \
  "${FROM_IMAGE}" "${TMP}.expected.full" \
  -i "${TO_IMAGE}" --wp=0 --sys_props ,-1 --force

test_update "Full update (from stdin)" \
  "${FROM_IMAGE}" "${TMP}.expected.full" \
  -i - --wp=0 --sys_props ,-1 --force <"${TO_IMAGE}"

test_update "Full update (GBB=0 -> 0)" \
  "${FROM_IMAGE}.gbb0" "${TMP}.expected.full.gbb0" \
  -i "${TO_IMAGE}" --wp=0

test_update "Full update (GBB flags -> 0x27)" \
  "${FROM_IMAGE}" "${TMP}.expected.full.gbb0x27" \
  -i "${TO_IMAGE}" --gbb_flags=0x27 --wp=0

test_update "Full update (--host_only)" \
  "${FROM_IMAGE}" "${TMP}.expected.full" \
  -i "${TO_IMAGE}" --wp=0 --host_only --ec_image non-exist.bin

test_update "Full update (GBB1.2 hwid digest)" \
  "${FROM_IMAGE}" "${TMP}.expected.full.gbb12" \
  -i "${TO_IMAGE_GBB12}" --wp=0

test_update "Full update (Preserve VPD using FMAP_AREA_PRESERVE)" \
  "${FROM_IMAGE}" "${TMP}.expected.full.empty_rw_vpd" \
  -i "${TO_IMAGE_WIPE_RW_VPD}" --wp=0


# Test RW-only update.
test_update "RW update" \
  "${FROM_IMAGE}" "${TMP}.expected.rw" \
  -i "${TO_IMAGE}" --wp=1

test_update "RW update (incompatible platform)" \
  "${FROM_IMAGE}" "!platform is not compatible" \
  -i "${LINK_BIOS}" --wp=1

test_update "RW update (incompatible rootkey)" \
  "${FROM_DIFFERENT_ROOTKEY_IMAGE}" "!RW signed by incompatible root key" \
  -i "${TO_IMAGE}" --wp=1

test_update "RW update (TPM Anti-rollback: data key)" \
  "${FROM_IMAGE}" "!Data key version rollback detected (2->1)" \
  -i "${TO_IMAGE}" --wp=1 --sys_props 1,0x20001

test_update "RW update (TPM Anti-rollback: kernel key)" \
  "${FROM_IMAGE}" "!Firmware version rollback detected (5->4)" \
  -i "${TO_IMAGE}" --wp=1 --sys_props 1,0x10005

# Test Try-RW update (vboot2).
test_update "RW update (A->B)" \
  "${FROM_IMAGE}" "${TMP}.expected.b" \
  -i "${TO_IMAGE}" -t --wp=1 --sys_props 0

test_update "RW update (B->A)" \
  "${FROM_IMAGE}" "${TMP}.expected.a" \
  -i "${TO_IMAGE}" -t --wp=1 --sys_props 1

test_update "RW update, same RO, wp=0 (A->B)" \
  "${FROM_SAME_RO_IMAGE}" "${TMP}.FROM_SAME_RO_IMAGE.expected.b" \
  -i "${TO_IMAGE}" -t --wp=0 --sys_props 0

test_update "RW update, same RO, wp=1 (A->B)" \
  "${FROM_SAME_RO_IMAGE}" "${TMP}.FROM_SAME_RO_IMAGE.expected.b" \
  -i "${TO_IMAGE}" -t --wp=1 --sys_props 0

test_update "RW update -> fallback to RO+RW Full update" \
  "${FROM_IMAGE}" "${TMP}.expected.full" \
  -i "${TO_IMAGE}" -t --wp=0 --sys_props 1,0x10002
test_update "RW update (incompatible platform)" \
  "${FROM_IMAGE}" "!platform is not compatible" \
  -i "${LINK_BIOS}" -t --wp=1

test_update "RW update (incompatible rootkey)" \
  "${FROM_DIFFERENT_ROOTKEY_IMAGE}" "!RW signed by incompatible root key" \
  -i "${TO_IMAGE}" -t --wp=1

test_update "RW update (TPM Anti-rollback: data key)" \
  "${FROM_IMAGE}" "!Data key version rollback detected (2->1)" \
  -i "${TO_IMAGE}" -t --wp=1 --sys_props 1,0x20001

test_update "RW update (TPM Anti-rollback: kernel key)" \
  "${FROM_IMAGE}" "!Firmware version rollback detected (5->4)" \
  -i "${TO_IMAGE}" -t --wp=1 --sys_props 1,0x10005

test_update "RW update -> fallback to RO+RW Full update (TPM Anti-rollback)" \
  "${FROM_IMAGE}" "!Firmware version rollback detected (6->4)" \
  -i "${TO_IMAGE}" -t --wp=0 --sys_props 1,0x10006

# Test 'factory mode'
test_update "Factory mode update (WP=0)" \
  "${FROM_IMAGE}" "${TMP}.expected.full" \
  -i "${TO_IMAGE}" --wp=0 --mode=factory

test_update "Factory mode update (WP=0)" \
  "${FROM_IMAGE}" "${TMP}.expected.full" \
  --factory -i "${TO_IMAGE}" --wp=0

test_update "Factory mode update (WP=1)" \
  "${FROM_IMAGE}" "!remove write protection for factory mode" \
  -i "${TO_IMAGE}" --wp=1 --mode=factory

test_update "Factory mode update (WP=1)" \
  "${FROM_IMAGE}" "!remove write protection for factory mode" \
  --factory -i "${TO_IMAGE}" --wp=1

test_update "Factory mode update (GBB=0 -> 0x39)" \
  "${FROM_IMAGE}.gbb0" "${TMP}.expected.full" \
  --factory -i "${TO_IMAGE}" --wp=0

# Test 'AP RO locked with verification turned on'
test_update "AP RO locked update (locked, SI_DESC is different)" \
  "${FROM_IMAGE}.locked" "${TMP}.expected.rw.locked" \
  -i "${TO_IMAGE}" --wp=0 --debug

test_update "AP RO locked update (locked, SI_DESC is the same)" \
  "${FROM_IMAGE}.locked_same_desc" "${TMP}.expected.full" \
  -i "${TO_IMAGE}" --wp=0 --debug

test_update "AP RO locked update (unlocked)" \
  "${FROM_IMAGE}.unlocked" "${TMP}.expected.full" \
  -i "${TO_IMAGE}" --wp=0 --debug

# Test legacy update
test_update "Legacy update" \
  "${FROM_IMAGE}" "${TMP}.expected.legacy" \
  -i "${TO_IMAGE}" --mode=legacy

# Test quirks
test_update "Full update (wrong size)" \
  "${FROM_IMAGE}.large" "!Failed writing firmware" \
  -i "${TO_IMAGE}" --wp=0 \
  --quirks unlock_csme_eve,eve_smm_store

test_update "Full update (--quirks enlarge_image)" \
  "${FROM_IMAGE}.large" "${TMP}.expected.large" --quirks enlarge_image \
  -i "${TO_IMAGE}" --wp=0

test_update "Full update (multi-line --quirks enlarge_image)" \
  "${FROM_IMAGE}.large" "${TMP}.expected.large" --quirks '
  enlarge_image
  ' -i "${TO_IMAGE}" --wp=0

test_update "Full update (--quirks unlock_csme_eve)" \
  "${FROM_IMAGE}" "${TMP}.expected.me_unlocked_eve" \
  --quirks unlock_csme_eve \
  -i "${TO_IMAGE}" --wp=0

test_update "Full update (failure by --quirks min_platform_version)" \
  "${FROM_IMAGE}" "!Need platform version >= 3 (current is 2)" \
  --quirks min_platform_version=3 \
  -i "${TO_IMAGE}" --wp=0 --sys_props ,,2

test_update "Full update (--quirks min_platform_version)" \
  "${FROM_IMAGE}" "${TMP}.expected.full" \
  --quirks min_platform_version=3 \
  -i "${TO_IMAGE}" --wp=0 --sys_props ,,3

test_update "Full update (incompatible platform)" \
  "${FROM_IMAGE}".unpatched "!platform is not compatible" \
  -i "${TO_IMAGE}" --wp=0

test_update "Full update (--quirks no_check_platform)" \
  "${FROM_IMAGE}".unpatched "${TMP}.expected.full" \
  --quirks no_check_platform \
  -i "${TO_IMAGE}" --wp=0

test_update "Full update (--quirks preserve_me with non-host programmer)" \
  "${FROM_IMAGE}" "${TMP}.expected.full" \
  --quirks preserve_me \
  -i "${TO_IMAGE}" --wp=0 \
  -p raiden_debug_spi:target=AP

test_update "Full update (--quirks preserve_me)" \
  "${FROM_IMAGE}" "${TMP}.expected.full" \
  --quirks preserve_me \
  -i "${TO_IMAGE}" --wp=0

test_update "Full update (--quirks preserve_me, autoupdate)" \
  "${FROM_IMAGE}" "${TMP}.expected.me_preserved" \
  --quirks preserve_me -m autoupdate \
  -i "${TO_IMAGE}" --wp=0

test_update "Full update (--quirks preserve_me, deferupdate_hold)" \
  "${FROM_IMAGE}" "${TMP}.expected.me_preserved" \
  --quirks preserve_me -m deferupdate_hold \
  -i "${TO_IMAGE}" --wp=0

test_update "Full update (--quirks preserve_me, factory)" \
  "${FROM_IMAGE}" "${TMP}.expected.full" \
  --quirks preserve_me -m factory \
  -i "${TO_IMAGE}" --wp=0

# Test manifest.
echo "TEST: Manifest (--manifest, -i, image.bin)"
cp -f "${GERALT_BIOS}" image.bin
"${FUTILITY}" update -i image.bin --manifest >"${TMP}.json.out"
cmp \
  <(jq -S <"${TMP}.json.out") \
  <(jq -S <"${SCRIPT_DIR}/futility/bios_geralt_cbfs.manifest.json")

# Test archive and manifest. CL_TAG is for custom_label_tag.
A="${TMP}.archive"
mkdir -p "${A}/bin"
echo "echo \"\${CL_TAG}\"" >"${A}/bin/vpd"
chmod +x "${A}/bin/vpd"

cp -f "${LINK_BIOS}" "${A}/bios.bin"
echo "TEST: Manifest (--manifest, -a, bios.bin)"
"${FUTILITY}" update -a "${A}" --manifest >"${TMP}.json.out"
cmp \
  <(jq -S <"${TMP}.json.out") \
  <(jq -S <"${SCRIPT_DIR}/futility/link_bios.manifest.json")

mv -f "${A}/bios.bin" "${A}/image.bin"
echo "TEST: Manifest (--manifest, -a, image.bin)"
"${FUTILITY}" update -a "${A}" --manifest >"${TMP}.json.out"
cmp \
  <(jq -S <"${TMP}.json.out") \
  <(jq -S <"${SCRIPT_DIR}/futility/link_image.manifest.json")


cp -f "${TO_IMAGE}" "${A}/image.bin"
test_update "Full update (--archive, single package)" \
  "${FROM_IMAGE}" "${TMP}.expected.full" \
  -a "${A}" --wp=0 --sys_props ,,3

echo "TEST: Output (--archive, --mode=output)"
TMP_OUTPUT="${TMP}.out_archive" && mkdir -p "${TMP_OUTPUT}"
"${FUTILITY}" update -a "${A}" --mode=output \
  --output_dir="${TMP_OUTPUT}"
cmp "${TMP_OUTPUT}/image.bin" "${TO_IMAGE}"

# Test Unified Build archives.
mkdir -p "${A}/keyset" "${A}/images"
cp -f "${SIGNER_CONFIG}" "${A}/"
cp -f "${LINK_BIOS}" "${A}/image.bin"
"${FUTILITY}" gbb -s --rootkey="${TMP}.from/rootkey" "${A}/image.bin"
"${FUTILITY}" load_fmap "${A}/image.bin" VBLOCK_A:"${TMP}.from/VBLOCK_A"
"${FUTILITY}" load_fmap "${A}/image.bin" VBLOCK_B:"${TMP}.from/VBLOCK_B"
mv -f "${A}/image.bin" "${A}/images/bios_coral.bin"
cp -f "${PEPPY_BIOS}" "${A}/images/bios_peppy.bin"
cp -f "${LINK_BIOS}" "${A}/images/bios_link.bin"
cp -f "${TMP}.to/rootkey" "${A}/keyset/rootkey.customtip-cl"
cp -f "${TMP}.to/VBLOCK_A" "${A}/keyset/vblock_A.customtip-cl"
cp -f "${TMP}.to/VBLOCK_B" "${A}/keyset/vblock_B.customtip-cl"
cp -f "${PEPPY_BIOS}" "${FROM_IMAGE}.ap"
cp -f "${LINK_BIOS}" "${FROM_IMAGE}.al"
cp -f "${VOXEL_BIOS}" "${FROM_IMAGE}.av"
patch_file "${FROM_IMAGE}.ap" FW_MAIN_A 0 "corrupted"
patch_file "${FROM_IMAGE}.al" FW_MAIN_A 0 "corrupted"
patch_file "${FROM_IMAGE}.av" FW_MAIN_A 0 "corrupted"
test_update "Full update (--archive, model=link)" \
  "${FROM_IMAGE}.al" "${LINK_BIOS}" \
  -a "${A}" --wp=0 --sys_props 0,0x10001,3 --model=link
test_update "Full update (--archive, model=peppy)" \
  "${FROM_IMAGE}.ap" "${PEPPY_BIOS}" \
  -a "${A}" --wp=0 --sys_props 0,0x10001,3 --model=peppy
test_update "Full update (--archive, model=unknown)" \
  "${FROM_IMAGE}.ap" "!Unsupported model: 'unknown'" \
  -a "${A}" --wp=0 --sys_props 0,0x10001,3 --model=unknown

test_update "Full update (--archive, detect-model)" \
  "${FROM_IMAGE}.ap" "${PEPPY_BIOS}" \
  -a "${A}" --wp=0 --sys_props 0,0x10001,3 \
  --programmer raiden_debug_spi:target=AP
test_update "Full update (--archive, detect-model, unsupported FRID)" \
  "${FROM_IMAGE}.av" "!Unsupported FRID: 'Google_Voxel'" \
  -a "${A}" --wp=0 --sys_props 0,0x10001,3 \
  --programmer raiden_debug_spi:target=AP

echo "*** Test Item: Detect model (--archive, --detect-model-only)"
"${FUTILITY}" update -a "${A}" \
  --emulate "${FROM_IMAGE}.ap" --detect-model-only >"${TMP}.model.out"
cmp "${TMP}.model.out" <(echo peppy)

test_update "Full update (--archive, custom label, signature_id=customtip-cl)" \
  "${FROM_IMAGE}.al" "${LINK_BIOS}" \
  -a "${A}" --wp=0 --sys_props 0,0x10001,3 --model=customtip \
  --signature_id=customtip-cl
CL_TAG="bad" PATH="${A}/bin:${PATH}" \
  test_update "Full update (--archive, custom label, wrong image)" \
  "${FROM_IMAGE}.al" "!The firmware image for custom label" \
  -a "${A}" --wp=0 --sys_props 0,0x10001,3 --debug --model=customtip
CL_TAG="cl" PATH="${A}/bin:${PATH}" \
  test_update "Full update (--archive, custom label, fake VPD)" \
  "${FROM_IMAGE}.al" "${LINK_BIOS}" \
  -a "${A}" --wp=0 --sys_props 0,0x10001,3 --model=customtip

# The output mode (without specifying signature id) for custom label would still
# need a source (emulate) image to decide the VPD, which is not a real use case.
echo "TEST: Output (--archive, --mode=output, custom label, signature_id)"
TMP_OUTPUT="${TMP}.out_custom_label" && mkdir -p "${TMP_OUTPUT}"
"${FUTILITY}" update -a "${A}" --mode=output \
  --output_dir="${TMP_OUTPUT}" --model=customtip \
  --signature_id=customtip-cl
cmp "${TMP_OUTPUT}/image.bin" "${LINK_BIOS}"

# Custom label + Unibuild with default keys as model name
cp -f "${TMP}.to/rootkey" "${A}/keyset/rootkey.customtip"
cp -f "${TMP}.to/VBLOCK_A" "${A}/keyset/vblock_A.customtip"
cp -f "${TMP}.to/VBLOCK_B" "${A}/keyset/vblock_B.customtip"
test_update "Full update (--archive, custom label, no VPD, default keys)" \
  "${FROM_IMAGE}.al" "${LINK_BIOS}" \
  -a "${A}" --wp=0 --sys_props 0,0x10001,3 --model=customtip

# Test special programmer
if type flashrom >/dev/null 2>&1; then
  echo "TEST: Full update (dummy programmer)"
  cp -f "${FROM_IMAGE}" "${TMP}.emu"
  "${FUTILITY}" update --programmer \
    dummy:emulate=VARIABLE_SIZE,image="${TMP}".emu,size=8388608 \
    -i "${TO_IMAGE}" --wp=0 --sys_props 0,0x10001,3 >&2
  cmp "${TMP}.emu" "${TMP}.expected.full"
fi

if type cbfstool >/dev/null 2>&1; then
  echo "SMM STORE" >"${TMP}.smm"
  truncate -s 262144 "${TMP}.smm"
  cp -f "${FROM_IMAGE}" "${TMP}.from.smm"
  cp -f "${TMP}.expected.full" "${TMP}.expected.full_smm"
  cbfstool "${TMP}.from.smm" add -r RW_LEGACY -n "smm_store" \
    -f "${TMP}.smm" -t raw
  cbfstool "${TMP}.expected.full_smm" add -r RW_LEGACY -n "smm_store" \
    -f "${TMP}.smm" -t raw -b 0x1bf000
  test_update "Legacy update (--quirks eve_smm_store)" \
    "${TMP}.from.smm" "${TMP}.expected.full_smm" \
    -i "${TO_IMAGE}" --wp=0 \
    --quirks eve_smm_store

  echo "min_platform_version=3" >"${TMP}.quirk"
  cp -f "${TO_IMAGE}" "${TO_IMAGE}.quirk"
  "${FUTILITY}" dump_fmap -x "${TO_IMAGE}" "BOOT_STUB:${TMP}.cbfs"
  # Create a fake CBFS using FW_MAIN_A size.
  truncate -s $((0x000dffc0)) "${TMP}.cbfs"
  "${FUTILITY}" load_fmap "${TO_IMAGE}.quirk" "FW_MAIN_A:${TMP}.cbfs"
  cbfstool "${TO_IMAGE}.quirk" add -r FW_MAIN_A -n updater_quirks \
    -f "${TMP}.quirk" -t raw
  test_update "Full update (failure by CBFS quirks)" \
    "${FROM_IMAGE}" "!Need platform version >= 3 (current is 2)" \
    -i "${TO_IMAGE}.quirk" --wp=0 --sys_props 0,0x10001,2
fi

if type ifdtool >/dev/null 2>&1; then
  test_update "Full update (--quirks unlock_csme, IFD chipset)" \
    "${FROM_IMAGE}" "${TMP}.expected.me_unlocked.ifd_chipset" \
    --quirks unlock_csme -i "${TO_IMAGE}.ifd_chipset" --wp=0

  test_update "Full update (--quirks unlock_csme, IFD bin path)" \
    "${FROM_IMAGE}" "${TMP}.expected.me_unlocked.ifd_path" \
    --quirks unlock_csme -i "${TO_IMAGE}.ifd_path" --wp=0

  test_update "Full update (--unlock_me)" \
    "${FROM_IMAGE}" "${TMP}.expected.me_unlocked.ifd_chipset" \
    --unlock_me -i "${TO_IMAGE}.ifd_chipset" --wp=0

  echo "TEST: Output (--mode=output, --quirks unlock_csme)"
  TMP_OUTPUT="${TMP}.out_csme" && mkdir -p "${TMP_OUTPUT}"
  mkdir -p "${TMP_OUTPUT}"
  "${FUTILITY}" update -i "${TMP}.expected.ifd_chipset" --mode=output \
    --output_dir="${TMP_OUTPUT}" --quirks unlock_csme
  cmp "${TMP_OUTPUT}/image.bin" "${TMP}.expected.me_unlocked.ifd_chipset"
fi

rm -rf "${TMP}"*
exit 0
