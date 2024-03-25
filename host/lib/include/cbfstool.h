/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdbool.h>

#include "2return_codes.h"
#include "2sha.h"

#define ENV_CBFSTOOL "CBFSTOOL"
#define DEFAULT_CBFSTOOL "cbfstool"

vb2_error_t cbfstool_truncate(const char *file, const char *region,
			      size_t *new_size);

/*
 * Check whether image under `file` path supports CBFS_VERIFICATION,
 * and contains metadata hash. Hash found is available under *hash. If it was
 * not found, then hash type will be set to VB2_HASH_INVALID.
 *
 * If `region` is NULL, then region option will not be passed to cbfstool.
 * Operations will be performed on default `COREBOOT` region.
 */
vb2_error_t cbfstool_get_metadata_hash(const char *file, const char *region,
				       struct vb2_hash *hash);

/*
 * Get value of a bool Kconfig option from "config" file in CBFS.
 *
 * This function extracts "config" file from selected region, parses it to find
 * value of `config_field`, and stores it in `value`. On failure, `value` will
 * be false.
 *
 * If `region` is NULL, then region option will not be passed to cbfstool.
 * Operations will be performed on default `COREBOOT` region.
 */
vb2_error_t cbfstool_get_config_bool(const char *file, const char *region,
				     const char *config_field, bool *value);

/*
 * Get value of a str Kconfig option from "config" file in CBFS.
 *
 * This is similar to cbfstool_get_config_bool(). On success, the extracted
 * value is stored in `value` as an allocated string (which has to be freed by
 * the caller). If the value is not found, an error will be returned, and
 * `value` will be NULL.
 */
vb2_error_t cbfstool_get_config_string(const char *file, const char *region,
				       const char *config_field, char **value);
