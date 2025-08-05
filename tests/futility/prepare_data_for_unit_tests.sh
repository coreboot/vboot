#!/bin/bash -eux
# Copyright 2025 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

SRC_RUN="$1"
DATA_PATH="${SRC_RUN}/tests/futility/data_copy"

# These have to be synced with defines in C test files.
IMAGE_MAIN="${DATA_PATH}/image.bin"
IMAGES_ARCHIVE="${DATA_PATH}/images.zip"
FILE_READONLY="${DATA_PATH}/read-only"

mkdir -p "${DATA_PATH}"
cp "${SRC_RUN}/tests/futility/data/image-steelix.bin" "${IMAGE_MAIN}"
cp "${SRC_RUN}/tests/futility/data/images.zip" "${IMAGES_ARCHIVE}"

touch "${FILE_READONLY}"
chmod 444 "${FILE_READONLY}"
