/* Copyright 2022 The ChromiumOS Authors.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "2common.h"
#include "2return_codes.h"
#include "subprocess.h"
#include "cbfstool.h"

static const char *get_cbfstool_path(void)
{
	static const char *cbfstool = NULL;

	if (cbfstool)
		return cbfstool;

	const char *env_cbfstool = getenv(ENV_CBFSTOOL);
	if (env_cbfstool && env_cbfstool[0] != '\0') {
		cbfstool = strdup(env_cbfstool);
		return cbfstool;
	}

	cbfstool = DEFAULT_CBFSTOOL;
	return cbfstool;
}

vb2_error_t cbfstool_truncate(const char *file, const char *region,
			      size_t *new_size)
{
	int status;
	char output_buffer[128];
	const char *cbfstool = get_cbfstool_path();

	struct subprocess_target output = {
		.type = TARGET_BUFFER_NULL_TERMINATED,
		.buffer = {
			.buf = output_buffer,
			.size = sizeof(output_buffer),
		},
	};
	const char *const argv[] = {
		cbfstool, file, "truncate", "-r", region, NULL,
	};

	VB2_DEBUG("Calling: %s '%s' truncate -r '%s'\n", cbfstool, file,
		  region);
	status = subprocess_run(argv, &subprocess_null, &output,
				&subprocess_null);

	if (status < 0) {
		fprintf(stderr, "%s(): cbfstool invocation failed: %m\n",
			__func__);
		exit(1);
	}

	/* Positive exit code means something is wrong with image. Return zero
	   as new size, because it might be problem with missing CBFS.*/
	if (status > 0) {
		*new_size = 0;
		return VB2_ERROR_CBFSTOOL;
	}

	if (sscanf(output_buffer, "%zi", new_size) != 1) {
		VB2_DEBUG("Failed to parse command output. Unexpected "
			  "output.\n");
		*new_size = 0;
		return VB2_ERROR_CBFSTOOL;
	}

	return VB2_SUCCESS;
}
