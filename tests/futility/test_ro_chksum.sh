#!/bin/bash -eux
# Copyright 2026 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

me=${0##*/}
TMP="$me.tmp"

# Work in scratch directory
cd "$OUTDIR"

DATADIR="${SCRIPT_DIR}/futility/data"
SHA256SUM="sha256sum"
SHA256_SIZE=32
DATA_SIZE=131040

set -o pipefail

infile_ec="${DATADIR}/helipilot_ec.bin"
tmpfile_ro="${TMP}.helipilot_wp_ro.bin"

outfile_chksum="${TMP}.ro_chksum.bin"
sha256sum_out="${TMP}.chksum.bin"
outfile_ec="${TMP}.helipilot_ec_chksum_signed.bin"

# Check that the required external variables exist
: "${OUTDIR:?Error: OUTDIR environment variable not set}"
: "${SCRIPT_DIR:?Error: SCRIPT_DIR environment variable not set}"
: "${FUTILITY:?Error: FUTILITY environment variable not set}"

if [[ ! -d "${OUTDIR}" ]]; then
    echo "Error: OUTDIR '${OUTDIR}' is not a directory." >&2
    exit 1
fi

if [[ ! -x "${FUTILITY}" ]]; then
    echo "Error: FUTILITY '${FUTILITY}' is not executable." >&2
    exit 1
fi

# ====================================================================
# Verify inputs
# ====================================================================
# Verify that input file exists
if [[ ! -e "${infile_ec}" ]]; then
    echo "Error: input file '${infile_ec}' is not found!" >&2
    exit 1
fi

# Verify that input file is not signed
if "${FUTILITY}" show --type ro_chksum "${infile_ec}"; then
    echo "Error: Input file '${infile_ec}' appears to be already signed." >&2
    exit 1
fi

# ====================================================================
# 1. Test Case #1 Create the checksum on RO section and verify output
# ====================================================================
# Create temporary RO file from input EC file
if ! "${FUTILITY}" dump_fmap -x "${infile_ec}" WP_RO:"${tmpfile_ro}"; then
    echo "Error: Can't dump WP_RO from '${infile_ec}' fmap." >&2
    exit 1
fi

# Verify that tmp RO file is not signed
if "${FUTILITY}" show --type ro_chksum "${tmpfile_ro}"; then
    echo "Error: Input file '${tmpfile_ro}' appears to be already signed." >&2
    exit 1
fi

# Create checksum for wp_ro
"${FUTILITY}" sign --type ro_chksum --data_size ${DATA_SIZE} \
                "${tmpfile_ro}" "${outfile_chksum}"

# Calculate checksum using linux shell commands, output to binary file
head -c ${DATA_SIZE} "${tmpfile_ro}" | "${SHA256SUM}" | cut -d ' ' -f 1 | xxd -r -p\
                > "${sha256sum_out}"

# Compare the two to ensure accuracy
if ! cmp "${outfile_chksum}" "${sha256sum_out}"; then
    echo "Error: Checksum mismatch between futility sign and shell calculation." >&2
    exit 1
fi

# Write the checksum to the tmp file
dd if="${outfile_chksum}" of="${tmpfile_ro}" bs=1 count=${SHA256_SIZE} \
                seek=${DATA_SIZE} conv=notrunc status=none;

# Verify that that temporary file is now correctly signed.
if ! "${FUTILITY}" show --type ro_chksum "${tmpfile_ro}"; then
    echo "Error: Checksum mismatch in output file" >&2
    exit 1
fi

# Also verify using the --fv option
if ! "${FUTILITY}" show --type ro_chksum --fv "${tmpfile_ro}" "${tmpfile_ro}"; then
    echo "Error: Checksum mismatch in output file" >&2
    exit 1
fi

# ===========================================
# 2. Test Case #2 Sign the RO of an ec binary
# ===========================================
# Create signed EC binary
"${FUTILITY}" sign --type ro_chksum \
                "${infile_ec}" "${outfile_ec}"

# Verify that that output file is now correctly signed.
if !("${FUTILITY}" show --type ro_chksum "${outfile_ec}"); then
    echo "Error: Checksum mismatch in output file" >&2
    exit 1
fi

# ====================================================
# 3. Test Case #3 Sign the RO of an ec binary in place
# ====================================================
# Overwrite output file with input file for in place signing
cp "${infile_ec}" "${outfile_ec}"

# Verify that output file is not signed
if "${FUTILITY}" show --type ro_chksum "${outfile_ec}"; then
    echo "Error: Input file '${outfile_ec}' appears to be already signed." >&2
    exit 1
fi

# Sign output file in place
"${FUTILITY}" sign --type ro_chksum "${outfile_ec}"

# Verify that that output file is now correctly signed.
if ! "${FUTILITY}" show --type ro_chksum "${outfile_ec}" ; then
    echo "Error: Checksum mismatch in output file" >&2
    exit 1
fi

cleanup() {
    rm -rf "${TMP}"*
}
trap cleanup EXIT
exit 0
