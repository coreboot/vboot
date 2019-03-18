#!/bin/bash
# Copyright 2018 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

. "$(dirname "$0")/common.sh"

load_shflags || exit 1

DEFINE_boolean override_keyid "${FLAGS_TRUE}" \
  "Override keyid from manifest." ""

FLAGS_HELP="Usage: ${PROG} [options] <input_dir> <key_dir> <output_image>

Signs <input_dir> with keys in <key_dir>.
"

# Parse command line.
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

# Abort on error and uninitialized variables.
set -e
set -u

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

# Sign cr50 RW firmware ELF images into a combined cr50 firmware image
# using the provided production keys and manifests.
sign_rw() {
  if [[ $# -ne 7 ]]; then
    die "Usage: sign_rw <key_file> <manifest> <fuses>" \
        "<rma_key_dir> <rw_a> <rw_b> <output>"
  fi

  local key_file="$1"
  local manifest_file="$2"
  local fuses_file="$3"
  local rma_key_dir="$4"
  local elfs=( "$5" "$6" )
  local result_file="$7"
  local temp_dir="$(make_temp_dir)"
  local rma_key_base

  if [[ ! -f "${result_file}" ]]; then
    die "${result_file} not found."
  fi

  # If signing a chip factory image (version 0.0.22) do not try figuring out the
  # RMA keys.
  local cr50_version="$(jq '.epoch * 10000 + .major * 100 + .minor' \
     "${manifest_file}")"

  if [[ "${cr50_version}" != "22" ]]; then
    rma_key_base="$(determine_rma_key_base "${rma_key_dir}" "${elfs[@]}")"
  else
    echo "Ignoring RMA keys for factory branch ${cr50_version}"
  fi

  local signer_command_params=(--b -x "${fuses_file}" --key "${key_file}")

  # Swap test public RMA server key with the prod version.
  if [[ -n "${rma_key_base}" ]]; then
    signer_command_params+=(
      --swap "${rma_key_base}.test","${rma_key_base}.prod"
    )
  fi
  signer_command_params+=(--json "${manifest_file}")

  signer_command_params+=(--format=bin)
  dst_suffix='flat'

  if [[ "${FLAGS_override_keyid}" == "${FLAGS_TRUE}" ]]; then
    signer_command_params+=(--override-keyid)
  fi

  local count=0
  for elf in "${elfs[@]}"; do
    if strings "${elf}" | grep -q "DBG/cr50"; then
      die "Will not sign debug image with prod keys"
    fi
    signed_file="${temp_dir}/${count}.${dst_suffix}"

    # Make sure output file is not owned by root.
    touch "${signed_file}"
    if ! cr50-codesigner "${signer_command_params[@]}" \
        -i "${elf}" -o "${signed_file}"; then
      die "cr50-codesigner ${signer_command_params[@]}" \
        "-i ${elf} -o ${signed_file} failed"
    fi

    if [[ -n "${rma_key_base}" ]]; then
      if find_blob_in_blob  "${signed_file}" "${rma_key_base}.test"; then
        die "test RMA key in the signed image!"
      fi

      if ! find_blob_in_blob "${signed_file}" "${rma_key_base}.prod"; then
        die "prod RMA key not in the signed image!"
      fi
    fi
    : $(( count++ ))
  done

  # Full binary image is required, paste the newly signed blobs into the
  # output image.
  dd if="${temp_dir}/0.${dst_suffix}" of="${result_file}" \
    seek=16384 bs=1 conv=notrunc
  dd if="${temp_dir}/1.${dst_suffix}" of="${result_file}" \
    seek=278528 bs=1 conv=notrunc
}

# A very crude RO verification function. The key signature found at a fixed
# offset into the RO blob must match the RO type. Prod keys have bit D2 set to
# one, dev keys have this bit set to zero.
verify_ro() {
  if [[ $# -ne 1 ]]; then
    die "Usage: verify_ro <ro_bin>"
  fi

  local ro_bin="$1"
  local key_byte

  if [[ ! -f "${ro_bin}" ]]; then
    die "${ro_bin} not a file!"
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

# This function prepares a full CR50 image, consisting of two ROs and two RWs
# placed at their respective offsets into the resulting blob. It invokes the
# bs (binary signer) script to actually convert ELF versions of RWs into
# binaries and sign them.
#
# The signed image is placed in the directory named as concatenation of RO and
# RW version numbers and board ID fields, if set to non-default. The ebuild
# downloading the tarball from the BCS expects the image to be in that
# directory.
sign_cr50_firmware() {
  if [[ $# -ne 9 ]]; then
    die "Usage: sign_cr50_firmware <key_file> <manifest> <fuses>" \
        "<rma_key_dir> <ro_a> <ro_b> <rw_a> <rw_b> <output>"
  fi

  local key_file="$1"
  local manifest_source="$2"
  local fuses_file="$3"
  local rma_key_dir="$4"
  local ro_a_hex="$5"
  local ro_b_hex="$6"
  local rw_a="$7"
  local rw_b="$8"
  local output_file="$9"
  local temp_dir="$(make_temp_dir)"
  local manifest_file

  # The H1 chip where Cr50 firmware runs has 512K of flash, the generated
  # image must match the flash size.
  IMAGE_SIZE="$(( 512 * 1024 ))"

  # Sanitize manifest released by the builder.
  manifest_file="${temp_dir}/$(basename "${manifest_source}")"
  if ! cr50-codesigner --convert-json --input "${manifest_source}" \
       --output "${manifest_file}"; then
    die "failed to convert ${manifest_source} into valid json"
  fi

  dd if=/dev/zero bs="${IMAGE_SIZE}" count=1 status=none |
    tr '\000' '\377' > "${output_file}"
  if [[ "$(stat -c '%s' "${output_file}")" != "${IMAGE_SIZE}" ]]; then
    die "Failed creating ${output_file}"
  fi

  local f
  local count=0
  for f in "${ro_a_hex}" "${ro_b_hex}"; do
    if ! objcopy -I ihex "${f}" -O binary "${temp_dir}/${count}.bin"; then
      die "Failed to convert ${f} from hex to bin"
    fi
    verify_ro "${temp_dir}/${count}.bin"
    : $(( count++ ))
  done

  if ! sign_rw "${key_file}" "${manifest_file}" "${fuses_file}" \
               "${rma_key_dir}" "${rw_a}" "${rw_b}" "${output_file}"; then
    die "Failed invoking sign_rw for ELF files ${rw_a} ${rw_b}"
  fi

  dd if="${temp_dir}/0.bin" of="${output_file}" conv=notrunc
  dd if="${temp_dir}/1.bin" of="${output_file}" seek=262144 bs=1 conv=notrunc

  echo "Image successfully signed to ${output_file}"
}

# Sign the directory holding cr50 firmware.
sign_cr50_firmware_dir() {
  if [[ $# -ne 3 ]]; then
    die "Usage: sign_cr50_firmware_dir <input> <key> <output>"
  fi

  local input="${1%/}"
  local key_file="$2"
  local output="$3"

  if [[ -d "${output}" ]]; then
    output="${output}/cr50.bin.prod"
  fi

  sign_cr50_firmware \
          "${key_file}" \
          "${input}/ec_RW-manifest-prod.json" \
          "${input}/fuses.xml" \
          "${input}" \
          "${input}/prod.ro.A" \
          "${input}/prod.ro.B" \
          "${input}/ec.RW.elf" \
          "${input}/ec.RW_B.elf" \
          "${output}"
}

main() {
  if [[ $# -ne 3 ]]; then
    flags_help
    exit 1
  fi

  local input="${1%/}"
  local key_dir="$2"
  local output="$3"

  local key_file="${key_dir}/cr50.pem"
  if [[ ! -e "${key_file}" ]]; then
    die "Missing key file: ${key_file}"
  fi

  if [[ ! -d "${input}" ]]; then
    die "Missing input directory: ${input}"
  fi

  sign_cr50_firmware_dir "${input}" "${key_file}" "${output}"
}
main "$@"
