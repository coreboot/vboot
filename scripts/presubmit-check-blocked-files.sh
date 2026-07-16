#!/usr/bin/env bash
# Copyright 2026 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Blocks commits that create or modify specific restricted files

# Define the list of blocked file names here
BLOCKED_FILES=(
  "Android.bp"
  "vboot.rc"
)

has_error=0

# ${PRESUBMIT_FILES} are passed as arguments to this script
for file in "$@"; do
  filename=$(basename "${file}")

  # Check if the current file matches any in our blocked list
  for blocked in "${BLOCKED_FILES[@]}"; do
    if [[ "${filename}" == "${blocked}" ]]; then
      echo "ERROR: Creating or modifying '${file}' is not allowed in this repository."
      has_error=$((has_error + 1))
      break # Stop checking this file and move to the next one
    fi
  done
done

exit "${has_error}"
