#!/bin/bash
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# shellcheck source=common.sh
. "$(dirname "$0")/common.sh"

load_shflags || exit 1

DEFINE_boolean override_keyid "${FLAGS_TRUE}" \
  "Override keyid from manifest." ""

# shellcheck disable=SC2154
FLAGS_HELP="Usage: ${PROG} [options] <input_dir> <cr50 key> `
                   `<ti50 key> <output_image>

Signs <input_dir> with keys specified.
"

# Parse command line.
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

# Abort on error and uninitialized variables.
set -e
set -u

PRE_PVT_BID_FLAG=0x10
MP_BID_FLAG=0x10000
NIGHTLY_BID_FLAG=0x20000

# Convert unsigned 32 bit value into a signed one.
to_int32() {
  local inp="$1"
  python -c \
         "import struct; \
          d=struct.pack('I', $inp); \
           print (struct.unpack('i', d)[0])"
}

# Functions allowing to determine the base address of a binary blob in ihex
# format. Invoked in a subprocess through () to be able to use stdout as the
# return values.

# In ihex format binary data is represented as a set of records. Each record
# is a text string of hex values in ASCII. All records start with a header
# which determines the record contents.
#
# The most common record type is the data record, its header includes the 16
# bit address of where the record data will have to be placed in the physical
# address space. Naturally 16 bits is not enough as of last thirty years, some
# special types of record are used to specify the segment base of there the
# 16 bit address is used as the offset.
#
# The segment base is still represented as a 16 bit value, depending on the
# record type the base is shifted right ether 4 (record type 02) or 16 (record
# type 04) bits.
#
# The first two records of the ihex binary blob are a segment record and a
# data record. Combining the segment value from the first record and the
# address value from the second record one can determine the base address
# where the blob is supposed to be placed.
#
# See https://en.wikipedia.org/wiki/Intel_HEX for further details.
parse_segment() {
  local string="$1"

  if [[ "${string}" =~ ^:020000 && "${#string}" -eq 15 ]]; then
    local type="${string:7:2}"
    local value="0x${string:9:4}"
    local segment

    case "${type}" in
      (02)
        segment=$(( value * 16 ))
        ;;
      (04)
        segment=$(( value * 65536 ))
        ;;
      (*)
        error "unknown segment record type ${type}"
        ;;
    esac
    printf "0x%x" "${segment}"
  else
    error "unexpected segment record: ${string}"
  fi
}

# The second record in the ihex binary blob is mapped to the lowest 16 bit
# address in the segment.
parse_data() {
  local string="$1"

  if [[ "${string}" =~ ^:10 && "${#string}" -eq 43 ]]; then
    echo "0x${string:3:4}"
  else
    error "unexpected data record: ${string}"
  fi
}

# Given an ihex binary blob determine its base address as a sum of the segment
# address and the offset of the first record into the segment.
get_hex_base() {
  local hexf="$1"
  local strings
  local segment
  local base_offset

  # Some ihex blobs include <cr><lf>, drop <cr> to allow for fixed size check.
  mapfile -t strings < <(head -2 "${hexf}" | sed 's/\x0d//')

  if [[ ${#strings[@]} != 2 ]]; then
    error "input file ${hexf} too short"
    return
  fi
  segment="$(parse_segment "${strings[0]}")"
  base_offset="$(parse_data "${strings[1]}")"

  if [[ -n "${segment}" && -n "${base_offset}" ]]; then
    printf "%d\n" $(( segment + base_offset ))
  else
    error "${hexf} does not seem to be a valid ihex module."
  fi
}

# Paste a binary blob into a larger binary file at a given offset.
paste_bin() {
  local file="${1}"
  local blob="${2}"
  local image_base="${3}"
  local hex_base="${4}"
  local file_size
  local blob_size
  local offset


  file_size="$(stat -c '%s' "${file}")"
  blob_size="$(stat -c '%s' "${blob}")"
  offset="$(( hex_base - image_base ))"

  if [[ $(( blob_size + offset )) -ge ${file_size} ]];then
    die \
      "Can't fit ${blob_size} bytes at offset ${offset} into ${file_size} bytes"
  fi
  dd if="${blob}" of="${file}" seek="${offset}" bs=1 conv=notrunc
}

# This function accepts two arguments, the name of the GSC manifest file which
# needs to be verified and in certain cases altered and the generation of the
# chip (h or g).
#
# The function verifies that the input manifest is a proper json file, and
# that the manifest conforms to GSC board ID flags conventions for various
# build images:

# - board IDs for node locked images come from signing instructions, and the
#   config1 manifest field value must have the 0x80000000 bit set.
#
# - when signing pre-pvt binaries (major version number is even) the 0x10
#   flags bit must be set.
#
# - when signing mp images (major version number is odd), the 0x10000 flags
#   bit must be set (this can be overridden by signing instructions).
#
# - when signing nightly images (major version number is 26), the flags are
#   0x20000
verify_and_prepare_gsc_manifest() {
  if [[ $# -ne 2 ]]; then
    die "Usage: verify_and_prepare_gsc_manifest <manifest .json file> <generation>"
  fi

  local manifest_json="$1"
  local generation="$2"

  local bid_flags
  local config1
  local epoch
  local major
  local minor
  local values

  mapfile -t values < <(jq '.config1,.epoch,.major,.minor,.board_id_flags' \
             "${manifest_json}")

  config1="${values[0]}"
  epoch="${values[1]}"
  major="${values[2]}"
  minor="${values[3]}"
  bid_flags="${values[4]}"

  if [[ ${major} == null ]]; then
    die "Major version number not found in ${manifest_json}"
  fi

  if [[ ${bid_flags} == null ]]; then
    die "bid_flags not found in ${manifest_json}"
  fi

  case "${INSN_TARGET:-}" in

    (Nightly)
      # At this point Nightly builds must have the major version 26 and
      # 0x20000 board id flags, so it can't run on released devices.
      if (( (major == 26 ) && (bid_flags == NIGHTLY_BID_FLAG) )); then
        # The Nightly target is only valid for ti50 devices.
        if [[ "${generation}" == "d" ]] ; then
          return 0
        fi
      fi
      ;;

    (NodeLocked)
      if [[ -z ${INSN_DEVICE_ID:-} ]]; then
        die "Node locked target without Device ID value"
      fi

      local sub
      local devid0
      local devid1

      devid0="$(to_int32 "0x${INSN_DEVICE_ID/-*}")"
      devid1="$(to_int32 "0x${INSN_DEVICE_ID/*-}")"
      cf1="$(to_int32 $(( 0x80000000 + config1 )))"
      sub="$(printf "   \"DEV_ID0\": %s,\\\n  \"DEV_ID1\": %s," \
                              "${devid0}" "${devid1}")"

      # Manifest fields must be modified as follows:
      #
      # - board_id related fields removed
      # - 'config1' field bit 0x80000000 set
      # - least significant bit of the 'tag' field originally set to all zeros
      #   changed from zero to one
      # - DEV_ID values spliced in into the 'fuses' section
      sed -i  "/board_id/d;\
        s/\"config1\":.*/\"config1\": ${cf1},/;\
        s/\(tag.*0\+\)0/\11/;\
        /\"fuses\":/ a\
            $sub"  "${manifest_json}" || die "Failed to edit the manifest"
      return 0
      ;;

    (PrePVT)
      # All we care about for pre pvt images is that major version number is
      # even and the 0x10 Board ID flag is set.
      if (( !(major & 1 ) && (bid_flags & PRE_PVT_BID_FLAG) )); then
        return 0
      fi
      ;;

    (ReleaseCandidate|GeneralRelease)
      if (( (bid_flags & MP_BID_FLAG) && (major & 1) )); then
        if [[ ${INSN_TARGET} == GeneralRelease ]]; then
          # Strip Board ID information for approved for release MP images.
          sed -i  "/board_id/d" "${manifest_json}"
        fi
        return 0
      fi
      ;;

    (*)
      die "Unsupported target '${INSN_TARGET:-}': " \
	  "generation = '${generation}' major = '${major}'"
  esac

  die "Inconsistent manifest ${manifest_json}: generation = '${generation}'," \
      "major = '${major}',board_id_flags = '${bid_flags}' " \
      "target = '${INSN_TARGET}'"
}

# This function accepts two arguments, names of two binary files.
#
# It searches the first passed-in file for the first 8 bytes of the second
# passed in file. The od utility is used to generate full hex dump of the
# first file (16 bytes per line) and the first 8 bytes of the second file.
# grep is used to check if the pattern is present in the full dump.
find_blob_in_blob() {
  if [[ $# -ne 2 ]]; then
    die "Usage: find_blob_in_blob <haystack> <needle>"
  fi

  local main_blob="$1"
  local pattern_blob="$2"
  local pattern
  # Show without offsets, single byte hex, no compression of zero runs.
  local od_options=("-An" "-tx1" "-v")

  # Get the first 8 bytes of the pattern blob.
  pattern="$(od "${od_options[@]}" -N8 "${pattern_blob}")"

  # Eliminate all newlines to be able to search the entire body as one unit.
  if od "${od_options[@]}" "${main_blob}" | \
     tr -d '\n' |
     grep -q -F "${pattern}"; then
    return 0
  fi

  return 1
}

# This function accepts two arguments, names of the two ELF files.
#
# The files are searched for test RMA public key patterns - x25519 or p256,
# both files are supposed to have pattern of one of these keys and not the
# other. If this holds true the function prints the public key base name. If
# not both files include the same key, or include more than one key, the
# function reports failure and exits the script.
determine_rma_key_base() {
  if [[ $# -ne 3 ]]; then
    die "Usage: determine_rma_key_base <rma_key_dir> <rw_a> <rw_b>"
  fi

  local rma_key_dir="$1"
  local elfs=( "$2" "$3" )
  local base_name="${rma_key_dir}/rma_key_blob"
  local curve
  local curves=( "x25519" "p256" )
  local elf
  local key_file
  local mask=1
  local result=0
  local rma_key_base

  for curve in "${curves[@]}"; do
    key_file="${base_name}.${curve}.test"
    for elf in "${elfs[@]}"; do
      if find_blob_in_blob "${elf}" "${key_file}"; then
        : $(( result |= mask ))
      fi
      : $(( mask <<= 1 ))
    done
  done

  case "${result}" in
    (3)  curve="x25519";;
    (12) curve="p256";;
    (*)  die "could not determine key type in the ELF files";;
  esac

  echo "${base_name}.${curve}"
}

# Sign GSC RW firmware ELF images into a combined GSC firmware image
# using the provided production keys and manifests.
sign_rw() {
  if [[ $# -ne 9 ]]; then
    die "Usage: sign_rw <key_file> <manifest> <fuses>" \
        "<rma_key_dir> <rw_a> <rw_b> <output> <generation> <image_base>"
  fi

  local key_file="$1"
  local manifest_file="$2"
  local fuses_file="$3"
  local rma_key_dir="$4"
  local rws=( "$5" "$6" )
  local result_file="$7"
  local generation="$8"
  local image_base="$9"
  local base_name
  local rma_key_base=""
  local signer_command_params
  local temp_dir
  local prohibited_blobs=()

  temp_dir="$(make_temp_dir)"
  signer_command_params=(-x "${fuses_file}" --key "${key_file}")

  case "${generation}"  in
    (h)
      # H1 image might require some tweaking.
      # If signing a chip factory image (version 0.0.22) do not try figuring
      # out the RMA keys.
      local gsc_version

      gsc_version="$(jq '.epoch * 10000 + .major * 100 + .minor' \
        "${manifest_file}")"

      if [[ "${gsc_version}" != "22" ]]; then
        rma_key_base="$(determine_rma_key_base "${rma_key_dir}" "${rws[@]}")"
      else
        warn "Ignoring RMA keys for factory branch ${gsc_version}"
      fi

      # Swap test public RMA server key with the prod version.
      if [[ -n "${rma_key_base}" ]]; then
        signer_command_params+=(
          --swap "${rma_key_base}.test,${rma_key_base}.prod"
        )
      fi

      # Indicate H1 signing.
      signer_command_params+=( "--b" )
      base_name="cr50"
      ;;
    (d)
      # Indicate D1 signing.
      signer_command_params+=( "--dauntless" "--ihex" )
      base_name="ti50"
      # Key and hashes used in dev, must not leak into prod signed images.
      prohibited_blobs=(
        "${rma_key_dir}/rma_test_pub_key.bin"
        "${rma_key_dir}/arv_2k_test_key_hash.bin"
        "${rma_key_dir}/arv_4k_test_key_hash.bin"
      )
      ;;
    (*)
      die "Unknown generation value \"${generation}\""
      ;;
  esac

  signer_command_params+=(--json "${manifest_file}")


  if [[ "${FLAGS_override_keyid}" == "${FLAGS_TRUE}" ]]; then
    signer_command_params+=(--override-keyid)
  fi

  for rw in "${rws[@]}"; do
    local hex_signed="${temp_dir}/hex_signed"
    local bin_signed="${temp_dir}/bin_signed"
    local hex_base
    local blob

    # Make sure output files are not owned by root.
    touch "${bin_signed}" "${hex_signed}"
    if ! gsc-codesigner "${signer_command_params[@]}" \
        -i "${rw}" -o "${hex_signed}"; then
      die "gsc-codesigner ${signer_command_params[*]}" \
        "-i ${rw} -o ${hex_signed} failed"
    fi

    if ! objcopy -I ihex "${hex_signed}" -O binary "${bin_signed}"; then
      die "Failed to convert ${rw} from hex to bin"
    fi

    if [[ -n "${rma_key_base}" ]]; then
      if find_blob_in_blob  "${bin_signed}" "${rma_key_base}.test"; then
        die "test RMA key in the signed image!"
      fi

      if ! find_blob_in_blob "${bin_signed}" "${rma_key_base}.prod"; then
        die "prod RMA key not in the signed image!"
      fi
    fi

    for blob in "${prohibited_blobs[@]}"; do
      if [[ ! -f ${blob} ]]; then
        die "${blob} not found in the GSC tarball"
      fi
      if find_blob_in_blob "${bin_signed}" "${blob}"; then
        die "${blob} found in signed image"
      fi
    done

    hex_base="$(get_hex_base "${hex_signed}")"
    paste_bin "${result_file}" "${bin_signed}" "${image_base}" "${hex_base}"
  done

  if strings "${rw}" | grep -q "DBG/${base_name}"; then
    die "Will not sign debug image with prod keys"
  fi

}

# A very crude RO verification function. The key signature found at a fixed
# offset into the RO blob must match the RO type. Prod keys have bit D2 set to
# one, dev keys have this bit set to zero.
#
# The check is bypassed if the key file directory name includes string 'test'.
verify_ro() {
  if [[ $# -ne 2 ]]; then
    die "Usage: verify_ro <ro_bin> <key_file>"
  fi

  local ro_bin="$1"
  local key_file="$2"
  local key_byte
  local key_path

  if [[ ! -f "${ro_bin}" ]]; then
    die "${ro_bin} not a file!"
  fi

  key_path="$(dirname "${key_file}")"
  if [[ ${key_path##*/} == *"test"* ]]; then
    info "Test run, ignoring key type verification"
    return 0
  fi

  # Key signature's lowest byte is byte #5 in the line at offset 0001a0.
  key_byte="$(od -Ax -t x1 -v "${ro_bin}" | awk '/0001a0/ {print $6}')"
  case "${key_byte}" in
    (?[4567cdef])
      return 0
      ;;
  esac

  die "RO key (${key_byte}) in ${ro_bin} does not match type prod"
}

# This function prepares a full H1 or DT GSC image, consisting of two ROs and
# two RWs placed at their respective offsets into the resulting blob. It
# invokes the bs (binary signer) script to actually convert ELF versions of
# RWs into binaries and sign them.
#
# The signed image is placed in the directory named as concatenation of RO and
# RW version numbers and board ID fields, if set to non-default. The ebuild
# downloading the tarball from the BCS expects the image to be in that
# directory.
sign_gsc_firmware() {
  if [[ $# -ne 10 ]]; then
    die "Usage: sign_gsc_firmware <key_file> <manifest> <fuses>" \
        "<rma_key_dir> <ro_a> <ro_b> <rw_a> <rw_b> <output> <generation>"
  fi

  local key_file="$1"
  local manifest_file="$2"
  local fuses_file="$3"
  local rma_key_dir="$4"
  local ro_a_hex="$5"
  local ro_b_hex="$6"
  local rw_a="$7"
  local rw_b="$8"
  local output_file="$9"
  local generation="${10}"
  local temp_dir
  local chip_name

  temp_dir="$(make_temp_dir)"

  case "${generation}"  in
    (h)
      # H1 flash size, image size must match.
      IMAGE_SIZE="$(( 512 * 1024 ))"
      IMAGE_BASE="0x40000"
      chip_name="cr50"
      ;;
    (d)
      # D2 flash size, image size must match.
      IMAGE_SIZE="$(( 1024 * 1024 ))"
      IMAGE_BASE="0x80000"
      chip_name="ti50"
      ;;
  esac

  verify_and_prepare_gsc_manifest "${manifest_file}" "${generation}"

  dd if=/dev/zero bs="${IMAGE_SIZE}" count=1 status=none |
    tr '\000' '\377' > "${output_file}"
  if [[ "$(stat -c '%s' "${output_file}")" != "${IMAGE_SIZE}" ]]; then
    die "Failed creating ${output_file}"
  fi

  if ! sign_rw "${key_file}" "${manifest_file}" "${fuses_file}" \
       "${rma_key_dir}" "${rw_a}" "${rw_b}" \
       "${output_file}" "${generation}" "${IMAGE_BASE}"; then
    die "Failed invoking sign_rw for ${rw_a} and ${rw_b}"
  fi

  local f
  for f in "${ro_a_hex}" "${ro_b_hex}"; do
    local hex_base
    local bin

    hex_base="$(get_hex_base "${f}")"
    bin="${temp_dir}/bin"

    if [[ -z ${hex_base} ]]; then
      die "Failed retrieving base address from ${f}"
    fi

    if ! objcopy -I ihex "${f}" -O binary "${bin}"; then
      die "Failed to convert ${f} from hex to bin"
    fi
    if [[ "${generation}" == "h" ]]; then
      verify_ro "${bin}" "${key_file}"
    fi

    paste_bin "${output_file}" "${bin}" "${IMAGE_BASE}" "${hex_base}"
  done

  # Tell the signer how to rename the @CHIP@ portion of the output.
  echo "${chip_name}" > "${output_file}.rename"

  info "Image successfully signed to ${output_file}"
}

# Given a file containing an ECDSA signature in ASN.1 wrapping extract the R
# and S components, change their endianness and concatenate them together in
# a single 64 byte blob.
ecdsa_sig_to_raw() {
  if [[ $# -ne 2 ]]; then
    die "Usage: ecdsa_sig_to_raw <ASN.1 DER ECDSA sig> <RAW ECDSA SIG>"
  fi

  local asn1_sig="$1"
  local raw_sig="$2"

  # When parsing the signature, the two components are printed as 32 byte hex
  # numbers in the following format:
  #    2:d=1  hl=2 l=  33 prim: INTEGER :<hex ascii value>
  # let's pick them up, reverse the values and save in a single blob
  for line in $(openssl asn1parse -inform der -in "${asn1_sig}" |
               awk -F: '/INTEGER/ {print $4}'); do
    echo "${line}" |
      xxd -r -p |
      /usr/bin/od -An -tx1 -w32 |
      tr ' ' '\n' |
      tac |
      xargs |
      sed 's/ //g'
  done | xxd -r -p > "${raw_sig}"
}

make_nt_image() {
  if [[ $# -ne 4 ]]; then
    die "Usage: `
        `make_nt_image <rom_ext_{a,b}> <signed_rw_bin> <output>"
  fi

  local rom_ext_a="$1"
  local rom_ext_b="$2"
  local signed_rw_bin="$3"
  local output="$4"

  local full_image_size_kb=1024
  local rw_kb_offset=64

  # Now build a full OT image
  tr '\000' '\377' < /dev/zero | dd of="${output}.tmp" \
                                        bs=1K count="${full_image_size_kb}" status=none
  for x in "${rom_ext_a}:0" "${rom_ext_b}:$(( full_image_size_kb/2 ))" \
                                "${signed_rw_bin}:${rw_kb_offset}" \
                                "${signed_rw_bin}:$(( full_image_size_kb/2 + rw_kb_offset ))"
  do
    local tuple

    # shellcheck disable=SC2206
    IFS=: tuple=( ${x} )
    dd if="${tuple[0]}" of="${output}.tmp" bs=1k seek="${tuple[1]}" \
       conv=notrunc status=none
  done
  mv "${output}.tmp" "${output}"
}

# Sign image with a cloud KMS key using openssl with a PKCS#11 plugin. This
# function expects KMS_PKCS11_CONFIG env variable to be the name of the
# appropriate yaml file, and KEYCFG_TI50_KEY to be the name of the key to pass
# to the openssl invocation.
openssl_sign_firmware() {
  if [[ $# -ne 5 ]]; then
    die "Usage: openssl_sign_firmware <rom_ext_{a,b}> <rw_bin> <ti50 key> <output>"
  fi

  if [[ -z ${KMS_PKCS11_CONFIG:-} ]]; then
    die "KMS_PKCS11_CONFIG must be defined in the environment"
  fi
  local rom_ext_a="$1"
  local rom_ext_b="$2"
  local rw_bin="$3"
  local ti50_key="$4"
  local output="$5"

  local hex_code_end
  local ot_tbs
  local sig_space_size
  local signature
  local signed_rw_bin
  local tmpd

  tmpd=$(make_temp_dir)

  ot_tbs="${tmpd}/tbs"
  signature="${tmpd}/signature"
  signed_rw_bin="${tmpd}/signed.bin"

  # Read the code end location from the manifest, where it is placed at offset
  # of 828 hardcoded below.
  hex_code_end="$(dd if="${rw_bin}"  bs=1 count=4 skip=828 status=none | \
                     /usr/bin/od -An -tx4 | awk '{print "0x"$1}')"

  # Signature space is allocated at offset zero of the image.
  sig_space_size=384
  # Extract the TBS section of the binary which is everything above the
  # signature until code end.
  dd if="${rw_bin}" of="${ot_tbs}" bs=1 skip="${sig_space_size}" \
     count=$(( hex_code_end - sig_space_size )) status=none

  (
    export KMS_PKCS11_CONFIG
    export PKCS11_MODULE_PATH

    openssl dgst -sha256 \
            -engine pkcs11 -keyform engine \
            -sign "${ti50_key}" \
            -out "${signature}" < "${ot_tbs}"
  )

  plug_in_signatures "${signature}" ""  "${rw_bin}" "${signed_rw_bin}"

  make_nt_image "${rom_ext_a}" "${rom_ext_b}" "${signed_rw_bin}" "${output}"

  # Tell the signer how to rename the @CHIP@ portion of the output.
  echo "ti50" > "${output}.rename"
}

plug_in_signatures() {
  local ecdsa_sig="$1"
  local spx_sig="$2"
  local rw_bin="$3"
  local signed_bin="$4"

  local tmp_signed_bin="${signed_bin}.tmp"

  cp "${rw_bin}" "${tmp_signed_bin}"

  if [[ -n ${ecdsa_sig} ]]; then
    local ecdsa_sig_raw="${ecdsa_sig}.raw"

    ecdsa_sig_to_raw "${ecdsa_sig}" "${ecdsa_sig_raw}"

    # ECDSA signature is at the very bottom of the binary
    dd if="${ecdsa_sig_raw}" of="${tmp_signed_bin}" conv=notrunc status=none
  fi

  if [[ -n ${spx_sig} ]]; then
    # During the build process, when SPX key is added to the image, the signature
    # space is also allocated so the image is extended to cover the space
    # which will eventually be taken by the SPX signature.
    #
    # We expect the manifest to point at the SPX signature at the very end of
    # the extended input binary blob.
    local spx_sig_offset

    spx_sig_offset=$(( "$(stat -c '%s' "${rw_bin}")" -
                       "$(stat -c '%s' "${spx_sig}")" ))
    dd if="${spx_sig}" of="${tmp_signed_bin}" seek="${spx_sig_offset}" bs=1 \
       conv=notrunc status=none
  fi
  mv "${tmp_signed_bin}" "${signed_bin}"
}

# Sign the directory holding GSC firmware.
sign_gsc_firmware_dir() {
  if [[ $# -ne 4 ]]; then
    die "Usage: sign_gsc_firmware_dir <input> <cr_50 key> <ti50 key> <output>"
  fi

  local input="${1%/}"
  local cr50_key="$2"
  local ti50_key="$3"
  local output="$4"
  local generation
  local rw_a
  local rw_b
  local manifest_source
  local manifest_file
  local key_file
  local base_name

   # shellcheck disable=SC2012
  if [[  -n $(ls "${input}"/pao* 2>/dev/null) ]]; then
    # This is an Opentitan tarball, sign it for ECDSA with Cloud KMS.
    openssl_sign_firmware "${input}/rom_ext.A" "${input}/rom_ext.B" \
                          "${input}/rw.bin.ecdsa" "${ti50_key}" "${output}"
    return
  fi
  manifest_source="${input}/prod.json"
  manifest_file="${manifest_source}.updated"

  # Verify signing manifest.
  jq . < "${manifest_source}" > "${manifest_file}" || \
    die "basic validation of ${manifest_source} failed"


  # Retrieve chip type from the manifest, if present, otherwise use h1.
  generation="$(jq ".generation" "${input}/prod.json" | sed 's/"//g')"
  case "${generation}"  in
    (h|null)
      generation="h"
      base_name="cr50"
      key_file="${cr50_key}"
      rw_a="${input}/ec.RW.elf"
      rw_b="${input}/ec.RW_B.elf"
      ;;
    (d)
      base_name="ti50"
      key_file="${ti50_key}"
      rw_a="${input}/rw_A.hex"
      rw_b="${input}/rw_B.hex"
      ;;
    (*)
      die "Unknown generation value \"${generation}\" in signing manifest"
      ;;
  esac

  if [[ ! -e "${key_file}" ]]; then
    die "Missing key file: ${key_file}"
  fi

  if [[ -d "${output}" ]]; then
    output="${output}/${base_name}.bin.prod"
  fi

  sign_gsc_firmware \
          "${key_file}" \
          "${manifest_file}" \
          "${input}/fuses.xml" \
          "${input}" \
          "${input}/prod.ro.A" \
          "${input}/prod.ro.B" \
          "${rw_a}" \
          "${rw_b}" \
          "${output}" \
          "${generation}"
}

main() {
  if [[ $# -ne 4 ]]; then
    flags_help
    exit 1
  fi

  local input="${1%/}"
  local cr50_key="$2"
  local ti50_key="$3"
  local output="$4"

  local signing_instructions="${input}/signing_instructions.sh"

  if [[ -f ${signing_instructions} ]]; then
    . "${signing_instructions}"
  else
    die "${signing_instructions} not found"
  fi

  if [[ ! -d "${input}" ]]; then
    die "Missing input directory: ${input}"
  fi

  sign_gsc_firmware_dir "${input}" "${cr50_key}" "${ti50_key}" "${output}"
}
main "$@"
