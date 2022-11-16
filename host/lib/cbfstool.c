/* Copyright 2022 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "2common.h"
#include "2crypto.h"
#include "2return_codes.h"
#include "cbfstool.h"
#include "host_misc.h"
#include "subprocess.h"
#include "vboot_host.h"

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

/* Requires null-terminated buffer */
static vb2_error_t extract_metadata_hash(const char *buf, struct vb2_hash *hash)
{
	enum vb2_hash_algorithm algo;
	const char *to_find = "\n[METADATA HASH]";
	char *algo_str = NULL;
	char *hash_str = NULL;
	vb2_error_t rv = VB2_ERROR_CBFSTOOL;

	const char *start = strstr(buf, to_find);
	if (start)
		start += strlen(to_find);

	if (start) {
		const int matches = sscanf(start, " %m[^:\n\t ]:%m[^:\n\t ]",
					   &algo_str, &hash_str);

		if (matches < 2)
			goto done;

		if (!algo_str || !vb2_lookup_hash_alg(algo_str, &algo) ||
		    algo == VB2_HASH_INVALID)
			goto done;
		hash->algo = algo;

		if (!hash_str ||
		    strlen(hash_str) != (vb2_digest_size(algo) * 2) ||
		    !parse_hash(&hash->raw[0], vb2_digest_size(algo), hash_str))
			goto done;

		if (!strstr(buf, "]\tfully valid"))
			goto done;

		rv = VB2_SUCCESS;
	}

done:
	if (rv != VB2_SUCCESS)
		hash->algo = VB2_HASH_INVALID;

	free(algo_str);
	free(hash_str);

	return rv;
}

vb2_error_t cbfstool_get_metadata_hash(const char *file, const char *region,
				       struct vb2_hash *hash)
{
	int status;
	const char *cbfstool = get_cbfstool_path();
	const size_t data_buffer_sz = 1024 * 1024;
	char *data_buffer = malloc(data_buffer_sz);
	vb2_error_t rv = VB2_ERROR_CBFSTOOL;

	if (!data_buffer)
		goto done;

	memset(hash, 0, sizeof(*hash));
	hash->algo = VB2_HASH_INVALID;

	struct subprocess_target output = {
		.type = TARGET_BUFFER_NULL_TERMINATED,
		.buffer = {
			.buf = data_buffer,
			.size = data_buffer_sz,
		},
	};
	const char *argv[] = {
		cbfstool, file, "print", "-kv",
		region ? "-r" : NULL, region, NULL
	};

	status = subprocess_run(argv, &subprocess_null, &output,
				&subprocess_null);

	if (status < 0) {
		fprintf(stderr, "%s(): cbfstool invocation failed: %m\n",
			__func__);
		exit(1);
	}

	if (status > 0)
		goto done;

	rv = extract_metadata_hash(data_buffer, hash);

done:
	free(data_buffer);
	return rv;
}

/* Requires null-terminated buffer */
static char *extract_config_value(const char *buf, const char *config_field)
{
	char *to_find = NULL;

	if (asprintf(&to_find, "\n%s=", config_field) == -1) {
		fprintf(stderr, "Out of Memory\n");
		VB2_DIE("Out of memory\n");
	}

	const char *start = strstr(buf, to_find);
	if (start)
		start += strlen(to_find);

	free(to_find);

	if (start) {
		char *end = strchr(start, '\n');
		if (end)
			return strndup(start, end - start);
	}

	return NULL;
}

vb2_error_t cbfstool_get_config_value(const char *file, const char *region,
				      const char *config_field, char **value)
{
	int status;
	const char *cbfstool = get_cbfstool_path();
	const size_t data_buffer_sz = 1024 * 1024;
	char *data_buffer = malloc(data_buffer_sz);
	vb2_error_t rv = VB2_ERROR_CBFSTOOL;

	*value = NULL;

	if (!data_buffer)
		goto done;

	struct subprocess_target output = {
		.type = TARGET_BUFFER_NULL_TERMINATED,
		.buffer = {
			.buf = data_buffer,
			.size = data_buffer_sz,
		},
	};
	const char *argv[] = {
		cbfstool, file, "extract", "-n", "config", "-f", "/dev/stdout",
		region ? "-r" : NULL, region, NULL
	};

	status = subprocess_run(argv, &subprocess_null, &output,
				&subprocess_null);

	if (status < 0) {
		fprintf(stderr, "%s(): cbfstool invocation failed: %m\n",
			__func__);
		exit(1);
	}

	if (status > 0)
		goto done;

	*value = extract_config_value(data_buffer, config_field);

	rv = VB2_SUCCESS;
done:
	free(data_buffer);
	return rv;
}
