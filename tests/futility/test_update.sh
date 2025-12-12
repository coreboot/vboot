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
EVE_BIOS="${DATA_DIR}/bios_eve.bin"
LINK_BIOS="${DATA_DIR}/bios_link_mp.bin"
TRULO_800_BIOS="${DATA_DIR}/bios_trulo.15217.800.bin"
TRULO_900_BIOS="${DATA_DIR}/bios_trulo.15217.900.bin"
RO_VPD_BLOB="${DATA_DIR}/ro_vpd.bin"
SIGNER_CONFIG="${DATA_DIR}/signer_config.csv"
IDENTITY_CSV="${DATA_DIR}/identity.csv"

# Work in scratch directory
cd "${OUTDIR}"
set -o pipefail

# Re-create the temp folders
TMP_FROM="${TMP}/from"
TMP_TO="${TMP}/to"
EXPECTED="${TMP}/expected"
rm -rf "${TMP}"
mkdir -p "${TMP_FROM}" "${TMP_TO}" "${EXPECTED}"

FROM_IMAGE="${TMP}/src.trulo.800"
TO_IMAGE="${TMP}/src.trulo.900"
cp -f "${TRULO_800_BIOS}" "${FROM_IMAGE}"
cp -f "${TRULO_900_BIOS}" "${TO_IMAGE}"
"${FUTILITY}" load_fmap "${FROM_IMAGE}" \
  RO_VPD:"${RO_VPD_BLOB}" RW_VPD:"${RO_VPD_BLOB}"

LINK_MP_IMAGE="${TMP}/src.link"
cp -f "${LINK_BIOS}" "${LINK_MP_IMAGE}"

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

erase_file() {
  local file="$1"
  local size
  size="$(stat -c %s "${file}")"
  # Write 0xff (\377) bytes.
  head -c "${size}" /dev/zero | LC_ALL=C tr '\000' '\377' > "${file}"
}

get_section() {
  local file="$1"
  local section="$2"
  local section_offset="$3"

  local fmap_info
  local base
  local offset
  local size

  fmap_info="$("${FUTILITY}" dump_fmap -p "${file}" "${section}")"
  base="$(echo "${fmap_info}" | sed 's/^[^ ]* //; s/ [^ ]*$//')"
  size="$(echo "${fmap_info}" | sed 's/^[^ ]* //; s/^[^ ]* //')"
  offset=$((base + section_offset))
  dd if="${file}" bs=1 skip="${offset}" count="${size}"
}

unpack_image() {
  local folder="${TMP}/$1"
  local image="$2"
  mkdir -p "${folder}"
  (cd "${folder}" && "${FUTILITY}" dump_fmap -x "../../${image}")
  "${FUTILITY}" gbb -g --rootkey="${folder}/rootkey" "${image}"
}

change_key() {
  local image="$1"
  local unpack_dir="$2"

  "${FUTILITY}" gbb -s --rootkey="${unpack_dir}/rootkey" "${image}"
  "${FUTILITY}" load_fmap "${image}" \
    "VBLOCK_A:${unpack_dir}/VBLOCK_A" \
    "VBLOCK_B:${unpack_dir}/VBLOCK_B"
}

# Unpack images so we can prepare expected results by individual sections.
unpack_image "from" "${FROM_IMAGE}"
unpack_image "to" "${TO_IMAGE}"
unpack_image "link_mp" "${LINK_MP_IMAGE}"

# Hack FROM_IMAGE so it has same root key as TO_IMAGE (for RW update).
FROM_DIFFERENT_ROOTKEY_IMAGE="${FROM_IMAGE}.diff_rootkey"
cp -f "${FROM_IMAGE}" "${FROM_DIFFERENT_ROOTKEY_IMAGE}"
"${FUTILITY}" gbb -s --rootkey="${TMP}/link_mp/rootkey" "${FROM_DIFFERENT_ROOTKEY_IMAGE}"

# Hack for quirks
FROM_IMAGE_SIZE="$(stat -c %s "${FROM_IMAGE}")"
cp -f "${FROM_IMAGE}" "${FROM_IMAGE}.large"
truncate -s "$(("${FROM_IMAGE_SIZE}" * 2))" "${FROM_IMAGE}.large"

# Create the FROM_SAME_RO_IMAGE using the RO from TO_IMAGE."
FROM_SAME_RO_IMAGE="${FROM_IMAGE}.same_ro"
cp -f "${FROM_IMAGE}" "${FROM_SAME_RO_IMAGE}"
"${FUTILITY}" load_fmap "${FROM_SAME_RO_IMAGE}" \
  "RO_SECTION:${TMP_TO}/RO_SECTION"

# Create FROM_INCOMPAT_PLATFORM_IMAGE.
FROM_INCOMPAT_PLATFORM_IMAGE="${FROM_IMAGE}.incompat_plat"
cp -f "${FROM_IMAGE}" "${FROM_INCOMPAT_PLATFORM_IMAGE}"
INCOMPAT_FWID="Google_Incompatible.11111.222.0"
patch_file "${FROM_INCOMPAT_PLATFORM_IMAGE}" RO_FRID 0x0 \
  "${INCOMPAT_FWID}"

# Generate expected results.
cp -f "${TO_IMAGE}" "${EXPECTED}/full"
cp -f "${FROM_IMAGE}" "${EXPECTED}/rw"
cp -f "${FROM_IMAGE}" "${EXPECTED}/a"
cp -f "${FROM_IMAGE}" "${EXPECTED}/b"
cp -f "${FROM_SAME_RO_IMAGE}" "${EXPECTED}/FROM_SAME_RO_IMAGE.b"
cp -f "${FROM_IMAGE}" "${EXPECTED}/legacy"
"${FUTILITY}" load_fmap "${EXPECTED}/full" \
  "RW_VPD:${TMP_FROM}/RW_VPD" \
  "RO_VPD:${TMP_FROM}/RO_VPD"
"${FUTILITY}" load_fmap "${EXPECTED}/rw" \
  "RW_SECTION_A:${TMP_TO}/RW_SECTION_A" \
  "RW_SECTION_B:${TMP_TO}/RW_SECTION_B" \
  "RW_SHARED:${TMP_TO}/RW_SHARED" \
  "RW_LEGACY:${TMP_TO}/RW_LEGACY"
"${FUTILITY}" load_fmap "${EXPECTED}/a" \
  "RW_SECTION_A:${TMP_TO}/RW_SECTION_A" \
  "RW_LEGACY:${TMP_TO}/RW_LEGACY"
"${FUTILITY}" load_fmap "${EXPECTED}/b" \
  "RW_SECTION_B:${TMP_TO}/RW_SECTION_B" \
  "RW_LEGACY:${TMP_TO}/RW_LEGACY"
"${FUTILITY}" load_fmap "${EXPECTED}/FROM_SAME_RO_IMAGE.b" \
  "RW_SECTION_B:${TMP_TO}/RW_SECTION_B" \
  "RW_LEGACY:${TMP_TO}/RW_LEGACY"
"${FUTILITY}" load_fmap "${EXPECTED}/legacy" \
  "RW_LEGACY:${TMP_TO}/RW_LEGACY"
cp -f "${EXPECTED}/full" "${EXPECTED}/full.gbb0"
"${FUTILITY}" gbb -s --flags=0 "${EXPECTED}/full.gbb0"
cp -f "${FROM_IMAGE}" "${FROM_IMAGE}.gbb0"
"${FUTILITY}" gbb -s --flags=0 "${FROM_IMAGE}.gbb0"
cp -f "${EXPECTED}/full" "${EXPECTED}/full.gbb0x27"
"${FUTILITY}" gbb -s --flags=0x27 "${EXPECTED}/full.gbb0x27"
cp -f "${EXPECTED}/full" "${EXPECTED}/large"
dd if=/dev/zero bs="${FROM_IMAGE_SIZE}" count=1 | tr '\000' '\377' >>"${EXPECTED}/large"

# A special image that doesn't preserve RW_VPD (FMAP_AREA_PRESERVE=0x08).
# RW_VPD FmapAreaHeader is at FMAP offset 0x302, so area_flags is at 0x32a.
TO_IMAGE_WIPE_RW_VPD="${TO_IMAGE}.wipe_rw_vpd"
cp -f "${TO_IMAGE}" "${TO_IMAGE_WIPE_RW_VPD}"
patch_file "${TO_IMAGE_WIPE_RW_VPD}" FMAP 0x32a "\x00"
cp -f "${EXPECTED}/full" "${EXPECTED}/full.empty_rw_vpd"
"${FUTILITY}" load_fmap "${EXPECTED}/full.empty_rw_vpd" \
  RW_VPD:"${TMP_TO}/RW_VPD"
patch_file "${EXPECTED}/full.empty_rw_vpd" FMAP 0x32a "\x00"

# Special "from" image with different ME.
FROM_DIFFERENT_ME_IMAGE="${FROM_IMAGE}.diff_me"
cp -f "${FROM_IMAGE}" "${FROM_DIFFERENT_ME_IMAGE}"
patch_file "${FROM_DIFFERENT_ME_IMAGE}" SI_ME 0 "corrupted"
cp -f "${EXPECTED}/full" "${EXPECTED}/me_preserved"
patch_file "${EXPECTED}/me_preserved" SI_ME 0 "corrupted"

# Special "to" image with changed fwid to match "from" image
FROM_IMAGE_FWID_RW_A="$( get_section "${FROM_IMAGE}" RW_FWID_A 0 | sed 's/\x00/\\0/g' )"
FROM_IMAGE_FWID_RO="$( get_section "${FROM_IMAGE}" RO_FRID 0 | sed 's/\x00/\\0/g' )"

TO_IMAGE_SAME_FWID="${TO_IMAGE}.diff_rw_fwid"
cp -f "${TO_IMAGE}" "${TO_IMAGE_SAME_FWID}"
patch_file "${TO_IMAGE_SAME_FWID}" RW_FWID_A 0 "${FROM_IMAGE_FWID_RW_A}"
patch_file "${TO_IMAGE_SAME_FWID}" RW_FWID_B 0 "${FROM_IMAGE_FWID_RW_A}"
patch_file "${TO_IMAGE_SAME_FWID}" RO_FRID 0 "${FROM_IMAGE_FWID_RO}"

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
  local emu="${TMP}/emu"
  local msg

  shift 3
  cp -f "${emu_src}" "${emu}"
  echo "*** Test Item: ${test_name}"
  if [ "${error_msg}" != "${expected}" ] && [ -n "${error_msg}" ]; then
    msg="$(! "${FUTILITY}" update --emulate "${emu}" "$@" 2>&1)"
    grep -qF -- "${error_msg}" <<<"${msg}"
  else
    "${FUTILITY}" update --emulate "${emu}" "$@"
    cmp "${emu}" "${expected}"
  fi
}

# --sys_props: mainfw_act, tpm_fwver, platform_ver, [wp_hw, wp_sw]
# tpm_fwver = <data key version:16><firmware version:16>.
# TO_IMAGE is signed with data key version = 1, firmware version = 4 => 0x10004.

# Test Full update.
test_update "Full update" \
  "${FROM_IMAGE}" "${EXPECTED}/full" \
  -i "${TO_IMAGE}" --wp=0

test_update "Full update (check fwid)" \
  "${FROM_IMAGE}" "${EXPECTED}/full" \
  -i "${TO_IMAGE}" --wp=0 --check-fwid

test_update "Full update (check fwid, same fwid)" \
  "${FROM_IMAGE}" "${FROM_IMAGE}" \
  -i "${TO_IMAGE_SAME_FWID}" --wp=0 --check-fwid

test_update "Full update (incompatible platform)" \
  "${FROM_INCOMPAT_PLATFORM_IMAGE}" "!platform is not compatible" \
  -i "${TO_IMAGE}" --wp=0

test_update "Full update (--quirks no_check_platform)" \
  "${FROM_INCOMPAT_PLATFORM_IMAGE}" "${EXPECTED}/full" \
  -i "${TO_IMAGE}" --wp=0 \
  --quirks no_check_platform

test_update "Full update (TPM Anti-rollback: data key)" \
  "${FROM_IMAGE}" "!Data key version rollback detected" \
  -i "${TO_IMAGE}" --wp=0 --sys_props 1,0x20001

test_update "Full update (TPM Anti-rollback: kernel key)" \
  "${FROM_IMAGE}" "!Firmware version rollback detected" \
  -i "${TO_IMAGE}" --wp=0 --sys_props 1,0x10005

test_update "Full update (TPM Anti-rollback: 0 as tpm_fwver)" \
  "${FROM_IMAGE}" "${EXPECTED}/full" \
  -i "${TO_IMAGE}" --wp=0 --sys_props ,0x0

test_update "Full update (TPM check failure due to invalid tpm_fwver)" \
  "${FROM_IMAGE}" "!Invalid tpm_fwver: -1" \
  -i "${TO_IMAGE}" --wp=0 --sys_props ,-1

test_update "Full update (Skip TPM check with --force)" \
  "${FROM_IMAGE}" "${EXPECTED}/full" \
  -i "${TO_IMAGE}" --wp=0 --sys_props ,-1 --force

test_update "Full update (from stdin)" \
  "${FROM_IMAGE}" "${EXPECTED}/full" \
  -i - --wp=0 --sys_props ,-1 --force <"${TO_IMAGE}"

test_update "Full update (GBB=0 -> 0)" \
  "${FROM_IMAGE}.gbb0" "${EXPECTED}/full.gbb0" \
  -i "${TO_IMAGE}" --wp=0

test_update "Full update (GBB flags -> 0x27)" \
  "${FROM_IMAGE}" "${EXPECTED}/full.gbb0x27" \
  -i "${TO_IMAGE}" --gbb_flags=0x27 --wp=0

test_update "Full update (--host_only)" \
  "${FROM_IMAGE}" "${EXPECTED}/full" \
  -i "${TO_IMAGE}" --wp=0 --host_only --ec_image non-exist.bin

test_update "Full update (Preserve VPD using FMAP_AREA_PRESERVE)" \
  "${FROM_IMAGE}" "${EXPECTED}/full.empty_rw_vpd" \
  -i "${TO_IMAGE_WIPE_RW_VPD}" --wp=0


# Test RW-only update.
test_update "RW update" \
  "${FROM_IMAGE}" "${EXPECTED}/rw" \
  -i "${TO_IMAGE}" --wp=1

test_update "RW update (check fwid)" \
  "${FROM_IMAGE}" "${EXPECTED}/rw" \
  -i "${TO_IMAGE}" --wp=1 --check-fwid

test_update "RW update (check fwid, same fwid)" \
  "${FROM_IMAGE}" "${FROM_IMAGE}" \
  -i "${TO_IMAGE_SAME_FWID}" --wp=1 --check-fwid

test_update "RW update (incompatible platform)" \
  "${FROM_INCOMPAT_PLATFORM_IMAGE}" "!platform is not compatible" \
  -i "${TO_IMAGE}" --wp=1

test_update "RW update (incompatible rootkey)" \
  "${FROM_DIFFERENT_ROOTKEY_IMAGE}" "!RW signed by incompatible root key" \
  -i "${TO_IMAGE}" --wp=1

test_update "RW update (TPM Anti-rollback: data key)" \
  "${FROM_IMAGE}" "!Data key version rollback detected" \
  -i "${TO_IMAGE}" --wp=1 --sys_props 1,0x20001

test_update "RW update (TPM Anti-rollback: kernel key)" \
  "${FROM_IMAGE}" "!Firmware version rollback detected" \
  -i "${TO_IMAGE}" --wp=1 --sys_props 1,0x10005

# Test Try-RW update (vboot2).
test_update "RW update (A->B)" \
  "${FROM_IMAGE}" "${EXPECTED}/b" \
  -i "${TO_IMAGE}" -t --wp=1 --sys_props 0

test_update "RW update (B->A)" \
  "${FROM_IMAGE}" "${EXPECTED}/a" \
  -i "${TO_IMAGE}" -t --wp=1 --sys_props 1

test_update "RW update, same RO, wp=0 (A->B)" \
  "${FROM_SAME_RO_IMAGE}" "${EXPECTED}/FROM_SAME_RO_IMAGE.b" \
  -i "${TO_IMAGE}" -t --wp=0 --sys_props 0

test_update "RW update, same RO, wp=1 (A->B)" \
  "${FROM_SAME_RO_IMAGE}" "${EXPECTED}/FROM_SAME_RO_IMAGE.b" \
  -i "${TO_IMAGE}" -t --wp=1 --sys_props 0

test_update "RW update -> fallback to RO+RW Full update" \
  "${FROM_IMAGE}" "${EXPECTED}/full" \
  -i "${TO_IMAGE}" -t --wp=0 --sys_props 1,0x10001
test_update "RW update (incompatible platform)" \
  "${FROM_INCOMPAT_PLATFORM_IMAGE}" "!platform is not compatible" \
  -i "${TO_IMAGE}" -t --wp=1

test_update "RW update (incompatible rootkey)" \
  "${FROM_DIFFERENT_ROOTKEY_IMAGE}" "!RW signed by incompatible root key" \
  -i "${TO_IMAGE}" -t --wp=1

test_update "RW update (TPM Anti-rollback: data key)" \
  "${FROM_IMAGE}" "!Data key version rollback detected" \
  -i "${TO_IMAGE}" -t --wp=1 --sys_props 1,0x20001

test_update "RW update (TPM Anti-rollback: kernel key)" \
  "${FROM_IMAGE}" "!Firmware version rollback detected" \
  -i "${TO_IMAGE}" -t --wp=1 --sys_props 1,0x10005

test_update "RW update -> fallback to RO+RW Full update (TPM Anti-rollback)" \
  "${FROM_IMAGE}" "!Firmware version rollback detected" \
  -i "${TO_IMAGE}" -t --wp=0 --sys_props 1,0x10005

# Test 'factory mode'
test_update "Factory mode update (WP=0)" \
  "${FROM_IMAGE}" "${EXPECTED}/full" \
  -i "${TO_IMAGE}" --wp=0 --mode=factory

test_update "Factory mode update (WP=0)" \
  "${FROM_IMAGE}" "${EXPECTED}/full" \
  --factory -i "${TO_IMAGE}" --wp=0

test_update "Factory mode update (WP=1)" \
  "${FROM_IMAGE}" "!remove write protection for factory mode" \
  -i "${TO_IMAGE}" --wp=1 --mode=factory

test_update "Factory mode update (WP=1)" \
  "${FROM_IMAGE}" "!remove write protection for factory mode" \
  --factory -i "${TO_IMAGE}" --wp=1

test_update "Factory mode update (GBB=0 -> 0x39)" \
  "${FROM_IMAGE}.gbb0" "${EXPECTED}/full" \
  --factory -i "${TO_IMAGE}" --wp=0

# Test legacy update
test_update "Legacy update" \
  "${FROM_IMAGE}" "${EXPECTED}/legacy" \
  -i "${TO_IMAGE}" --mode=legacy

# Test quirks
test_update "Full update (--quirks enlarge_image)" \
  "${FROM_IMAGE}.large" "${EXPECTED}/large" --quirks enlarge_image \
  -i "${TO_IMAGE}" --wp=0

test_update "Full update (multi-line --quirks enlarge_image)" \
  "${FROM_IMAGE}.large" "${EXPECTED}/large" --quirks '
  enlarge_image
  ' -i "${TO_IMAGE}" --wp=0

test_update "Full update (failure by --quirks min_platform_version)" \
  "${FROM_IMAGE}" "!Need platform version >= 3 (current is 2)" \
  --quirks min_platform_version=3 \
  -i "${TO_IMAGE}" --wp=0 --sys_props ,,2

test_update "Full update (--quirks min_platform_version)" \
  "${FROM_IMAGE}" "${EXPECTED}/full" \
  --quirks min_platform_version=3 \
  -i "${TO_IMAGE}" --wp=0 --sys_props ,,3

test_update "Full update (--quirks preserve_me with non-host programmer)" \
  "${FROM_DIFFERENT_ME_IMAGE}" "${EXPECTED}/full" \
  --quirks preserve_me \
  -i "${TO_IMAGE}" --wp=0 \
  -p raiden_debug_spi:target=AP

test_update "Full update (--quirks preserve_me)" \
  "${FROM_DIFFERENT_ME_IMAGE}" "${EXPECTED}/full" \
  --quirks preserve_me \
  -i "${TO_IMAGE}" --wp=0

test_update "Full update (--quirks preserve_me, autoupdate)" \
  "${FROM_DIFFERENT_ME_IMAGE}" "${EXPECTED}/me_preserved" \
  --quirks preserve_me -m autoupdate \
  -i "${TO_IMAGE}" --wp=0

test_update "Full update (--quirks preserve_me, deferupdate_hold)" \
  "${FROM_DIFFERENT_ME_IMAGE}" "${EXPECTED}/me_preserved" \
  --quirks preserve_me -m deferupdate_hold \
  -i "${TO_IMAGE}" --wp=0

test_update "Full update (--quirks preserve_me, factory)" \
  "${FROM_DIFFERENT_ME_IMAGE}" "${EXPECTED}/full" \
  --quirks preserve_me -m factory \
  -i "${TO_IMAGE}" --wp=0

# Test manifest.
TMP_JSON_OUT="${TMP}/json.out"
echo "TEST: Manifest (--manifest, --image)"
cp -f "${GERALT_BIOS}" "${TMP}/image.bin"
(cd "${TMP}" &&
 "${FUTILITY}" update -i image.bin --manifest) >"${TMP_JSON_OUT}"
cmp \
  <(jq -S <"${TMP_JSON_OUT}") \
  <(jq -S <"${SCRIPT_DIR}/futility/bios_geralt_cbfs.manifest.json")

TMP_PARSEABLE_OUT="${TMP}/manifest.parseable"
echo "TEST: Manifest parseable (--parseable-manifest, --image)"
(cd "${TMP}" &&
 "${FUTILITY}" update -i image.bin --parseable-manifest) >"${TMP_PARSEABLE_OUT}"
cmp \
  <(sort "${TMP_PARSEABLE_OUT}") \
  <(sort "${SCRIPT_DIR}/futility/bios_geralt_cbfs.manifest.parseable")

# Test archive and manifest. CL_TAG is for custom_label_tag.
A="${TMP}/archive"
mkdir -p "${A}/bin"
echo 'echo "${CL_TAG}"' >"${A}/bin/vpd"
chmod +x "${A}/bin/vpd"

cp -f "${LINK_BIOS}" "${A}/bios.bin"
echo "TEST: Manifest (--manifest, -a, bios.bin)"
"${FUTILITY}" update -a "${A}" --manifest >"${TMP_JSON_OUT}"
cmp \
  <(jq -S <"${TMP_JSON_OUT}") \
  <(jq -S <"${SCRIPT_DIR}/futility/link_bios.manifest.json")

echo "TEST: Manifest parseable (--parseable-manifest, -a, bios.bin)"
"${FUTILITY}" update -a "${A}" --parseable-manifest >"${TMP_PARSEABLE_OUT}"
diff -u \
  <(sort "${TMP_PARSEABLE_OUT}") \
  <(sort "${SCRIPT_DIR}/futility/link_bios.manifest.parseable")

mv -f "${A}/bios.bin" "${A}/image.bin"
echo "TEST: Manifest (--manifest, -a, image.bin)"
"${FUTILITY}" update -a "${A}" --manifest >"${TMP_JSON_OUT}"
cmp \
  <(jq -S <"${TMP_JSON_OUT}") \
  <(jq -S <"${SCRIPT_DIR}/futility/link_image.manifest.json")

echo "TEST: Manifest parseable (--parseable-manifest, -a, image.bin)"
"${FUTILITY}" update -a "${A}" --parseable-manifest >"${TMP_PARSEABLE_OUT}"
diff -u \
  <(sort "${TMP_PARSEABLE_OUT}") \
  <(sort "${SCRIPT_DIR}/futility/link_image.manifest.parseable")

cp -f "${TO_IMAGE}" "${A}/image.bin"
test_update "Full update (--archive, single package)" \
  "${FROM_IMAGE}" "${EXPECTED}/full" \
  -a "${A}" --wp=0 --sys_props ,,3

echo "TEST: Output (--archive, --mode=output)"
TMP_OUTPUT="${TMP}/out_archive" && mkdir -p "${TMP_OUTPUT}"
"${FUTILITY}" update -a "${A}" --mode=output \
  --output_dir="${TMP_OUTPUT}"
cmp "${TMP_OUTPUT}/image.bin" "${TO_IMAGE}"

# Test Unified Build archives.
FROM_MP_IMAGE="${FROM_IMAGE}.mp"
cp -f "${FROM_IMAGE}" "${FROM_MP_IMAGE}"
change_key "${FROM_MP_IMAGE}" "${TMP}/link_mp"
TO_MP_IMAGE="${TO_IMAGE}.mp"
cp -f "${TO_IMAGE}" "${TO_MP_IMAGE}"
change_key "${TO_MP_IMAGE}" "${TMP}/link_mp"
cp -f "${EXPECTED}/full" "${EXPECTED}/full_mp"
change_key "${EXPECTED}/full_mp" "${TMP}/link_mp"

mkdir -p "${A}/keyset" "${A}/images"
cp -f "${SIGNER_CONFIG}" "${A}/"
rm -f "${A}/*.bin"
cp -f "${LINK_BIOS}" "${A}/images/bios_link.bin"
cp -f "${TRULO_900_BIOS}" "${A}/images/bios_trulo_900.bin"
cp -f "${GERALT_BIOS}" "${A}/images/bios_geralt.bin"
# TRULO_900_BIOS is dev-signed. Generate rootkey/VBLOCK patches with MP key
# to simulate a different custom label key.
unpack_image "to_mp" "${TO_MP_IMAGE}"
cp -f "${TMP}/to_mp/rootkey" "${A}/keyset/rootkey.customtip-mp"
cp -f "${TMP}/to_mp/VBLOCK_A" "${A}/keyset/vblock_A.customtip-mp"
cp -f "${TMP}/to_mp/VBLOCK_B" "${A}/keyset/vblock_B.customtip-mp"
cp -f "${LINK_MP_IMAGE}" "${LINK_MP_IMAGE}.corrupted"
cp -f "${LINK_MP_IMAGE}" "${LINK_MP_IMAGE}.erased"
patch_file "${LINK_MP_IMAGE}.corrupted" FW_MAIN_A 0 "corrupted"
erase_file "${LINK_MP_IMAGE}.erased"

test_update "Full update (--archive, model=link)" \
  "${LINK_MP_IMAGE}.corrupted" "${LINK_MP_IMAGE}" \
  -a "${A}" --wp=0 --sys_props 0,0x10001,3 --model=link
test_update "Full update (--archive, model=unknown)" \
  "${LINK_MP_IMAGE}.corrupted" "!Unsupported model: 'unknown'" \
  -a "${A}" --wp=0 --sys_props 0,0x10001,3 --model=unknown

# Test archives with identity.csv
cp -f "${IDENTITY_CSV}" "${A}/"
LINK_SKU_ID=0x1000
test_update "Full update (--archive, identity.csv with SKU ${LINK_SKU_ID})" \
  "${LINK_MP_IMAGE}.corrupted" "${LINK_MP_IMAGE}" \
  -a "${A}" --wp=0 --sys_props "0,0x10001,3,,,,${LINK_SKU_ID}"
WRONG_SKU_ID="0x999"
test_update "Full update (--archive, identity.csv with wrong SKU)" \
  "${LINK_MP_IMAGE}.corrupted" "!Failed to get device identity from identity.csv" \
  -a "${A}" --wp=0 --sys_props "0,0x10001,3,,,,${WRONG_SKU_ID}"
test_update "Full update (--archive, identity.csv with --sku-id)" \
  "${LINK_MP_IMAGE}.corrupted" "${LINK_MP_IMAGE}" \
  -a "${A}" --wp=0 --sys_props "0,0x10001,3,,,,${WRONG_SKU_ID}" \
  --sku-id "${LINK_SKU_ID}"

# Remotely flash over a completely erased system flash.
# The FRID matching is case-insensitive, so passing "google_link" is fine.
# `--programmer` is for simulating remote flashing (via servo).
# `--force` is required to ignore the system firmware parsing error.
test_update "Full update (--archive, remote, identity.csv with --frid/--sku-id)" \
  "${LINK_MP_IMAGE}.erased" "${LINK_MP_IMAGE}" \
  -a "${A}" --wp=0 --sys_props 0,0x10001,3 \
  --programmer raiden_debug_spi:target=AP \
  --frid "google_link" --sku-id "${LINK_SKU_ID}" --force

# Test --detect-model-only on a remote DUT.
echo "*** Test Item: Detect model (--archive, remote, --detect-model-only)"
"${FUTILITY}" update -a "${A}" \
  --emulate "${LINK_MP_IMAGE}.corrupted" --programmer raiden_debug_spi:target=AP \
  --detect-model-only >"${TMP}/model.out"
cmp "${TMP}/model.out" <(echo link)

cp -f "${LINK_MP_IMAGE}" "${LINK_MP_IMAGE}.incompat"
patch_file "${LINK_MP_IMAGE}.incompat" RO_FRID 0x0 \
  "Google_Incompatible.11111.222.0"
test_update "Detect model (--archive, remote, --detect-model-only, unsupported FRID)" \
  "${LINK_MP_IMAGE}.incompat" "!Unsupported model: 'Google_Incompatible'" \
  -a "${A}" --wp=0 --sys_props 0,0x10001,3 \
  --programmer raiden_debug_spi:target=AP \
  --detect-model-only

test_update "Full update (--archive, custom label with tag specified)" \
  "${FROM_MP_IMAGE}" "${EXPECTED}/full_mp" \
  -a "${A}" --wp=0 --sys_props 0,0x10001,3 --model=customtip-mp
CL_TAG="mp" PATH="${A}/bin:${PATH}" \
  test_update "Full update (--archive, custom label, fake VPD)" \
  "${FROM_MP_IMAGE}" "${EXPECTED}/full_mp" \
  -a "${A}" --wp=0 --sys_props 0,0x10001,3 --model=customtip
CL_TAG="bad" PATH="${A}/bin:${PATH}" \
  test_update "Full update (--archive, custom label, wrong image)" \
  "${FROM_MP_IMAGE}" "!The firmware image for custom label" \
  -a "${A}" --wp=0 --sys_props 0,0x10001,3 --debug --model=customtip

# The output mode (without specifying signature id) for custom label would still
# need a source (emulate) image to decide the VPD, which is not a real use case.
echo "TEST: Output (--archive, --mode=output, custom label with tag specified)"
TMP_OUTPUT="${TMP}/out_custom_label" && mkdir -p "${TMP_OUTPUT}"
"${FUTILITY}" update -a "${A}" --mode=output \
  --output_dir="${TMP_OUTPUT}" --model=customtip-mp
cmp "${TMP_OUTPUT}/image.bin" "${TO_MP_IMAGE}"

# Custom label + Unibuild with default keys as model name
cp -f "${TMP_TO}/rootkey" "${A}/keyset/rootkey.customtip"
cp -f "${TMP_TO}/VBLOCK_A" "${A}/keyset/vblock_A.customtip"
cp -f "${TMP_TO}/VBLOCK_B" "${A}/keyset/vblock_B.customtip"
test_update "Full update (--archive, custom label, no VPD, default keys)" \
  "${FROM_IMAGE}" "${EXPECTED}/full" \
  -a "${A}" --wp=0 --sys_props 0,0x10001,3 --model=customtip

# Test special programmer
test_flashrom() {
  echo "TEST: Full update (dummy programmer)"
  local emu="${TMP}/emu"
  cp -f "${FROM_IMAGE}" "${emu}"
  "${FUTILITY}" update --programmer \
    dummy:emulate=VARIABLE_SIZE,image="${emu}",size="${FROM_IMAGE_SIZE}" \
    -i "${TO_IMAGE}" --wp=0 --sys_props 0,0x10001,3 >&2
  cmp "${emu}" "${EXPECTED}/full"
}
type flashrom >/dev/null 2>&1 && test_flashrom

test_cbfstool() {
  echo "TEST: Update with cbsfstool"
  local smm="${TMP}/smm"
  local cbfs="${TMP}/cbfs"
  local quirk="${TMP}/quirk"
  local size

  cp -f "${EVE_BIOS}" "${TMP_FROM}.eve.locked"
  patch_file "${TMP_FROM}.eve.locked" SI_DESC 0x80 \
    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
  cp -f "${EVE_BIOS}" "${EXPECTED}/eve.unlocked"
  patch_file "${EXPECTED}/eve.unlocked" SI_DESC 0x80 \
    "\x00\xff\xff\xff\x00\xff\xff\xff\x00\xff\xff\xff"

  echo "SMM STORE" >"${smm}"
  truncate -s 262144 "${smm}"
  cbfstool "${TMP_FROM}.eve.locked" add -r RW_LEGACY -n "smm_store" \
    -f "${smm}" -t raw
  cbfstool "${EXPECTED}/eve.unlocked" add -r RW_LEGACY -n "smm_store" \
    -f "${smm}" -t raw -b 0x1bf000
  # Both unlock_csme_eve and eve_smm_store are implicitly enabled.
  test_update "Full update (--quirks unlock_csme_eve)" \
    "${TMP_FROM}.eve.locked" "${EXPECTED}/eve.unlocked" \
    -i "${EVE_BIOS}" --wp=0 \
    --quirks unlock_csme_eve
  test_update "Legacy update (--quirks eve_smm_store)" \
    "${TMP_FROM}.eve.locked" "${EXPECTED}/eve.unlocked" \
    -i "${EVE_BIOS}" --wp=0 \
    --quirks eve_smm_store

  cp "${TMP_FROM}.eve.locked" "${TMP_FROM}.eve.large"
  size="$(stat -c %s "${TMP_FROM}.eve.large")"
  truncate -s "$(("${size}" * 2))" "${TMP_FROM}.eve.large"
  test_update "Full update (wrong size)" \
    "${TMP_FROM}.eve.large" "!Failed writing firmware" \
    -i "${EVE_BIOS}" --wp=0 \
    --quirks unlock_csme_eve,eve_smm_store

  echo "min_platform_version=3" >"${quirk}"
  cp -f "${TO_IMAGE}" "${TO_IMAGE}.quirk"
  # Remove existing 'updater_quirks' if any.
  cbfstool "${TO_IMAGE}.quirk" remove -r FW_MAIN_A -n updater_quirks || true
  cbfstool "${TO_IMAGE}.quirk" add -r FW_MAIN_A -n updater_quirks \
    -f "${quirk}" -t raw
  test_update "Full update (failure by CBFS quirks)" \
    "${FROM_IMAGE}" "!Need platform version >= 3 (current is 2)" \
    -i "${TO_IMAGE}.quirk" --wp=0 --sys_props 0,0x10001,2
}
type cbfstool >/dev/null 2>&1 && test_cbfstool

# Add the given line to the config file in CBFS.
add_config() {
  local image="$1"
  local config_line="$2"
  local config_file="${TMP}/config"

  cbfstool "${image}" extract -n config -f "${config_file}"
  echo "${config_line}" >>"${config_file}"
  cbfstool "${image}" remove -n config
  cbfstool "${image}" add -n config -f "${config_file}" -t raw
}

# Remove lines of the given pattern from the config file in CBFS.
remove_config() {
  local image="$1"
  local config_pattern="$2"
  local config_file="${TMP}/config"

  cbfstool "${image}" extract -n config -f "${config_file}"
  sed -i "/${config_pattern}/d" "${config_file}"
  cbfstool "${image}" remove -n config
  cbfstool "${image}" add -n config -f "${config_file}" -t raw
}

lock_me() {
  local image="$1"

  ifdtool -p adl --lock "${image}" -O "${image}.tmp"
  ifdtool -p adl --gpr0-enable "${image}.tmp" -O "${image}"
}

unlock_me() {
  local image="$1"

  ifdtool -p adl --unlock "${image}" -O "${image}.tmp"
  ifdtool -p adl --gpr0-disable "${image}.tmp" -O "${image}"
}

test_ifdtool() {
  cp -f "${FROM_IMAGE}" "${FROM_IMAGE}.locked"
  lock_me "${FROM_IMAGE}.locked"
  cp -f "${FROM_IMAGE}" "${FROM_IMAGE}.unlocked"
  unlock_me "${FROM_IMAGE}.unlocked"
  cp -f "${TO_IMAGE}" "${TO_IMAGE}.locked"
  lock_me "${TO_IMAGE}.locked"
  cp -f "${TO_IMAGE}" "${TO_IMAGE}.unlocked"
  unlock_me "${TO_IMAGE}.unlocked"

  cp -f "${EXPECTED}/full" "${EXPECTED}/full.locked"
  lock_me "${EXPECTED}/full.locked"
  cp -f "${EXPECTED}/rw" "${EXPECTED}/rw.locked"
  lock_me "${EXPECTED}/rw.locked"

  # Test 'AP RO locked with verification turned on'.
  test_update "AP RO locked update (locked, SI_DESC is different)" \
    "${FROM_IMAGE}.locked" "${EXPECTED}/rw.locked" \
    -i "${TO_IMAGE}.unlocked" --wp=0 --debug

  test_update "AP RO locked update (locked, SI_DESC is the same)" \
    "${FROM_IMAGE}.locked" "${EXPECTED}/full.locked" \
    -i "${TO_IMAGE}.locked" --wp=0 --debug

  test_update "AP RO locked update (unlocked)" \
    "${FROM_IMAGE}.unlocked" "${EXPECTED}/full" \
    -i "${TO_IMAGE}" --wp=0 --debug

  # Generate images for testing --unlock_me.
  # There are two ways to detect the platform:
  #  1. Read CONFIG_IFD_CHIPSET from config file in CBFS
  #  2. Fallback for nissa: check if CONFIG_IFD_BIN_PATH contains 'nissa'
  local config_ifd_chipset='CONFIG_IFD_CHIPSET="adl"'
  local config_ifd_path=\
'CONFIG_IFD_BIN_PATH="3rdparty/blobs/mainboard/google/nissa/descriptor-craask.bin"'

  cp -f "${TO_IMAGE}" "${TO_IMAGE}.ifd"
  cp -f "${EXPECTED}/full" "${EXPECTED}/full.ifd"
  remove_config "${TO_IMAGE}.ifd" "CONFIG_IFD_CHIPSET="
  remove_config "${TO_IMAGE}.ifd" "CONFIG_IFD_BIN_PATH="
  remove_config "${EXPECTED}/full.ifd" "CONFIG_IFD_CHIPSET="
  remove_config "${EXPECTED}/full.ifd" "CONFIG_IFD_BIN_PATH="
  cp -f "${TO_IMAGE}.ifd" "${TO_IMAGE}.ifd_chipset"
  cp -f "${TO_IMAGE}.ifd" "${TO_IMAGE}.ifd_path"
  cp -f "${EXPECTED}/full.ifd" "${EXPECTED}/ifd_chipset"
  cp -f "${EXPECTED}/full.ifd" "${EXPECTED}/ifd_path"
  add_config "${TO_IMAGE}.ifd_chipset" "${config_ifd_chipset}"
  add_config "${TO_IMAGE}.ifd_path" "${config_ifd_path}"
  add_config "${EXPECTED}/ifd_chipset" "${config_ifd_chipset}"
  add_config "${EXPECTED}/ifd_path" "${config_ifd_path}"

  cp -f "${EXPECTED}/ifd_chipset" "${EXPECTED}/me_unlocked.ifd_chipset"
  cp -f "${EXPECTED}/ifd_path" "${EXPECTED}/me_unlocked.ifd_path"
  unlock_me "${EXPECTED}/me_unlocked.ifd_chipset"
  unlock_me "${EXPECTED}/me_unlocked.ifd_path"

  test_update "Full update (--quirks unlock_csme, IFD chipset)" \
    "${FROM_IMAGE}" "${EXPECTED}/me_unlocked.ifd_chipset" \
    --quirks unlock_csme -i "${TO_IMAGE}.ifd_chipset" --wp=0

  test_update "Full update (--quirks unlock_csme, IFD bin path)" \
    "${FROM_IMAGE}" "${EXPECTED}/me_unlocked.ifd_path" \
    --quirks unlock_csme -i "${TO_IMAGE}.ifd_path" --wp=0

  test_update "Full update (--unlock_me)" \
    "${FROM_IMAGE}" "${EXPECTED}/me_unlocked.ifd_chipset" \
    --unlock_me -i "${TO_IMAGE}.ifd_chipset" --wp=0

  echo "TEST: Output (--mode=output, --quirks unlock_csme)"
  TMP_OUTPUT="${TMP}/out_csme" && mkdir -p "${TMP_OUTPUT}"
  mkdir -p "${TMP_OUTPUT}"
  "${FUTILITY}" update -i "${EXPECTED}/ifd_chipset" --mode=output \
    --output_dir="${TMP_OUTPUT}" --quirks unlock_csme
  cmp "${TMP_OUTPUT}/image.bin" "${EXPECTED}/me_unlocked.ifd_chipset"
}
type ifdtool >/dev/null 2>&1 && test_ifdtool

rm -rf "${TMP}"
exit 0
