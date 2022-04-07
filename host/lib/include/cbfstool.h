/* Copyright 2022 The ChromiumOS Authors.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "2return_codes.h"

#define ENV_CBFSTOOL "CBFSTOOL"
#define DEFAULT_CBFSTOOL "cbfstool"

vb2_error_t cbfstool_truncate(const char *file, const char *region,
			      size_t *new_size);
