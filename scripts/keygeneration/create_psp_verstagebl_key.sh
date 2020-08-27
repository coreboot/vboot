#!/bin/bash
# Copyright 2020 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

usage() {
  cat <<EOF
Usage: $0 <OUTPUT DIRECTORY> <KEY SIZE> [PASSPHRASE]

Generate a key pair for signing the PSP_Verstage binary to be loaded by
the PSP bootloader.  For detail, reference the AMD documentation titled
"OEM PSP VERSTAGE BL FW Signing Key Pair Generation and Certificate Request
Process" - http://dr/corp/drive/folders/1ySJyDgbH73W1lqrhxMvM9UYl5TtJt_mw

Arguments:
- Output Directory: Location for the keys to be generated.  Must exist.
- Key size: 2048 for Picasso, Dali, & Pollock, 4096 for other F17h SOCs
- Passphrase: optional passphrase.  If not given on the command line, or in
    the environment variable "PASSPHRASE", it will be requested at runtime.

EOF

  if [[ $# -ne 0 ]]; then
    echo "$*" >&2
    exit 1
  else
    exit 0
  fi
}

KEYNAME=psp_verstagebl_fw_signing

main() {
  set -e

  # Check arguments
  if [[ $# -lt 2 ]]; then
    usage "Error: Too few arguments"
  fi
  if [[ ! ($2 -eq 2048 || $2 -eq 4096) ]]; then
    usage "Error: invalid keysize"
  fi
  if [[ $# -eq 3 ]]; then
    export PASSPHRASE=$3
  fi
  if [[ $# -gt 3 ]]; then
    usage "Error: Too many arguments"
  fi

  local dir=$1
  local keysize=$2
  local hash

  if [[ ${keysize} -eq 2048 ]]; then
    hash="sha256"
  else
    hash="sha384"
  fi

  cat <<EOF >"${dir}/${KEYNAME}.cnf"
[req]
default_md         = ${hash}
prompt             = no
distinguished_name = req_distinguished_name
req_extensions     = v3_req

[req_distinguished_name]
countryName             = US
stateOrProvinceName     = CA
localityName            = Mountain View
organizationalUnitName  = Google LLC
commonName              = AMD Reference PSP Verstage BL FW Certificate

# Google Platform Vendor ID [31:24] = 0x94 other bits [23:0] are reserved
serialNumber            = 94000000

[v3_req]
basicConstraints     = CA:FALSE
keyUsage             = nonRepudiation, digitalSignature, keyEncipherment
subjectKeyIdentifier = hash
EOF

  local cmd=(
    openssl req -new
    -newkey "rsa:${keysize}"
    -config "${dir}/${KEYNAME}.cnf"
    -keyout "${dir}/${KEYNAME}.key"
    -out "${dir}/${KEYNAME}.csr"
  )
  if [[ "${PASSPHRASE+set}" == "set" ]]; then
    cmd+=(-passout env:PASSPHRASE)
  fi
  "${cmd[@]}"

  echo
  echo "The following hash should be communicated to AMD separately from the CSR"
  echo "to allow it to be verified."
  openssl dgst -sha256 ${KEYNAME}.csr

  rm -f "${dir}/${KEYNAME}.cnf"
}

main "$@"
