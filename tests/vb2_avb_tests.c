/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for keyblock hash verification
 */
#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>

#include "2avb.h"
#include "2common.h"
#include "2struct.h"
#include "common/tests.h"
#include "host_key.h"

static const char *const key_len[] = {"1024", "2048", "4096", "8192"};
static int key_alg[] = {VB2_ALG_RSA1024_SHA256, VB2_ALG_RSA2048_SHA256, VB2_ALG_RSA4096_SHA256,
			VB2_ALG_RSA8192_SHA256};

static uint8_t workbuf[VB2_FIRMWARE_WORKBUF_RECOMMENDED_SIZE]
	__attribute__((aligned(VB2_WORKBUF_ALIGN)));
static struct vb2_context *vb2_ctx;
static struct vb2_shared_data *sd;
static uint8_t *avb_key_data;
static size_t avb_key_len;
static char *keys_dir;

static int prepare_cros_key(const char *filename, uint32_t alg)
{
	struct vb2_packed_key *test_key;

	test_key = vb2_read_packed_keyb(filename, alg, 1);
	if (!test_key) {
		fprintf(stderr, "Error reading test key\n");
		return -1;
	}
	sd->kernel_key_offset = sizeof(*sd);
	sd->kernel_key_size =
		sizeof(*test_key) + vb2_packed_key_size(vb2_crypto_to_signature(alg));
	memcpy(sd + 1, test_key, sd->kernel_key_size);
	free(test_key);

	return 0;
}

static int prepare_avb_key(const char *filename)
{
	FILE *fp;
	struct stat sb;
	int rv = 0;

	fp = fopen(filename, "rb");
	if (!fp) {
		fprintf(stderr, "Couldn't open file %s!\n", filename);
		return -1;
	}

	if (fstat(fileno(fp), &sb)) {
		fprintf(stderr, "Can't fstat %s: %s\n", filename, strerror(errno));
		goto err;
	}

	avb_key_len = sb.st_size;
	avb_key_data = malloc(sb.st_size);
	if (!avb_key_data)
		goto err;

	if (fread(avb_key_data, avb_key_len, 1, fp) != 1) {
		fprintf(stderr, "Unable to read from %s: %s\n", filename, strerror(errno));
		goto err;
	}

	fclose(fp);
	return 0;

err:
	if (avb_key_data) {
		free(avb_key_data);
		avb_key_data = NULL;
		avb_key_len = 0;
	}
	fclose(fp);
	return rv;
}

static int setup(int key_num)
{
	char filename[256];

	snprintf(filename, sizeof(filename), "%s/key_rsa%s.keyb", keys_dir, key_len[key_num]);
	if (prepare_cros_key(filename, key_alg[key_num])) {
		fprintf(stderr, "Error preparing AVB key\n");
		return -1;
	}

	snprintf(filename, sizeof(filename), "%s/key_rsa%s.avb", keys_dir, key_len[key_num]);
	if (prepare_avb_key(filename)) {
		fprintf(stderr, "Error preparing AVB key\n");
		return -1;
	}

	return 0;
}

static void clean(void)
{
	if (avb_key_data) {
		free(avb_key_data);
		avb_key_data = NULL;
	}

	avb_key_len = 0;
}

int main(int argc, char *argv[])
{
	AvbIOResult ret;
	bool key_is_trusted;
	AvbOps *avb_ops;
	int i;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <keys_dir>", argv[0]);
		return -1;
	}

	keys_dir = argv[1];

	/* Set up context */
	if (vb2api_init(workbuf, sizeof(workbuf), &vb2_ctx)) {
		printf("Failed to initialize workbuf.\n");
		return -1;
	}

	sd = vb2_get_sd(vb2_ctx);
	avb_ops = vboot_avb_ops_new(vb2_ctx, NULL, NULL, NULL, NULL);

	for (i = 0; i < ARRAY_SIZE(key_len); i++) {

		// Successful validation
		TEST_EQ_S(setup(i), 0);
		ret = avb_ops->validate_vbmeta_public_key(avb_ops, avb_key_data, avb_key_len,
							  NULL, 0, &key_is_trusted);
		TEST_EQ(ret, AVB_IO_RESULT_OK, "validate_vbmeta_public_key - successful");
		TEST_EQ(key_is_trusted, true, "Key is trusted");
		clean();

		// Key size lesser than required
		TEST_EQ_S(setup(i), 0);
		avb_key_len = sizeof(AvbRSAPublicKeyHeader) - 1;
		ret = avb_ops->validate_vbmeta_public_key(avb_ops, avb_key_data, avb_key_len,
							  NULL, 0, &key_is_trusted);
		TEST_EQ(ret, AVB_IO_RESULT_OK, "validate_vbmeta_public_key - successful");
		TEST_EQ(key_is_trusted, false, "Key rejected - incorrect key size");
		clean();

		// n0inv corruption
		TEST_EQ_S(setup(i), 0);
		avb_key_data[4] ^= avb_key_data[4];
		ret = avb_ops->validate_vbmeta_public_key(avb_ops, avb_key_data, avb_key_len,
							  NULL, 0, &key_is_trusted);
		TEST_EQ(ret, AVB_IO_RESULT_OK, "validate_vbmeta_public_key - successful");
		TEST_EQ(key_is_trusted, false, "Key rejected - n0inv corrupted");
		clean();

		// rr corruption
		TEST_EQ_S(setup(i), 0);
		avb_key_data[avb_key_len - 1] ^= avb_key_data[avb_key_len - 1];
		ret = avb_ops->validate_vbmeta_public_key(avb_ops, avb_key_data, avb_key_len,
							  NULL, 0, &key_is_trusted);
		TEST_EQ(ret, AVB_IO_RESULT_OK, "validate_vbmeta_public_key - successful");
		TEST_EQ(key_is_trusted, false, "Key rejected - rr corrupted");
		clean();

		// n corruption
		TEST_EQ_S(setup(i), 0);
		avb_key_data[sizeof(AvbRSAPublicKeyHeader)] ^=
			avb_key_data[sizeof(AvbRSAPublicKeyHeader)];
		ret = avb_ops->validate_vbmeta_public_key(avb_ops, avb_key_data, avb_key_len,
							  NULL, 0, &key_is_trusted);
		TEST_EQ(ret, AVB_IO_RESULT_OK, "validate_vbmeta_public_key - successful");
		TEST_EQ(key_is_trusted, false, "Key rejected - n corrupted");
		clean();
	}

	// Try 2 different keys of the same length
	char filename[256];
	snprintf(filename, sizeof(filename), "%s/key_rsa2048_exp3.keyb", keys_dir);
	TEST_EQ(prepare_cros_key(filename, VB2_ALG_RSA2048_SHA256), 0, "Prepare cros key");
	snprintf(filename, sizeof(filename), "%s/key_rsa2048.avb", keys_dir);
	TEST_EQ(prepare_avb_key(filename), 0, "Prepare avb key");
	ret = avb_ops->validate_vbmeta_public_key(avb_ops, avb_key_data, avb_key_len, NULL, 0,
						  &key_is_trusted);
	TEST_EQ(ret, AVB_IO_RESULT_OK, "validate_vbmeta_public_key - successful");
	TEST_EQ(key_is_trusted, false, "Key rejected - different keys");

	vboot_avb_ops_free(avb_ops);

	return gTestSuccess ? 0 : 255;
}
