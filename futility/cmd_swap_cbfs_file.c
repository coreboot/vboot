/* Copyright 2026 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <endian.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "2common.h"
#include "2crypto.h"
#include "2sha.h"
#include "cbfstool.h"
#include "file_type.h"
#include "fmap.h"
#include "futility.h"
#include "futility_options.h"
#include "host_common.h"
#include "host_key21.h"
#include "host_misc.h"
#include "updater_utils.h"

#define CBFS_ECRW_NAME "ecrw"
#define CBFS_ECRW_HASH_NAME "ecrw.hash"
#define CBFS_ECRW_VERSION_NAME "ecrw.version"
#define CBFS_ECRW_CONFIG_NAME "ecrw.config"

#define COOKIE1_SIGNATURE 0xce778899U
#define COOKIE2_SIGNATURE 0xceaabbddU
#define COOKIE2_OFFSET 44U
#define SIZE_OFFSET 36U
#define MAX_COOKIE_SEARCH_OFFSET 4096U

static const char *const fmap_regions[] = {
	"FW_MAIN_A",
	"FW_MAIN_B",
};

enum {
	OPT_EC_CONFIG = 1000,
};

static const struct option long_opts[] = {
	{"image", 1, NULL, 'i'},
	{"ec", 1, NULL, 'e'},
	{"ec_config", 1, NULL, OPT_EC_CONFIG},
	{"ec-config", 1, NULL, OPT_EC_CONFIG},
	{"ap_for_ec", 1, NULL, 'a'},
	{"ap-for-ec", 1, NULL, 'a'},
	{"raw_ecrw", 1, NULL, 'r'},
	{"raw-ecrw", 1, NULL, 'r'},
	{"ec_ver", 1, NULL, 'v'},
	{"ec-ver", 1, NULL, 'v'},
	{"keyset", 1, NULL, 'K'},
	{"help", 0, NULL, 'h'},
	{NULL, 0, NULL, 0},
};

static const char usage[] =
	"\n"
	"Usage:  " MYNAME " %s [OPTIONS]\n"
	"\n"
	"Swap the EC RW (ecrw) binary within an AP firmware (BIOS) image.\n"
	"\n"
	"Options:\n"
	"  -i, --image <FILE>             AP firmware file to modify\n"
	"  -e, --ec <FILE>                EC firmware file (e.g. 'ec.bin')\n"
	"  --ec_config <FILE>             EC config file (default: "
	"'ec.config')\n"
	"  -a, --ap_for_ec <FILE>         AP firmware file as source of EC RW\n"
	"  -r, --raw_ecrw <FILE>          Raw EC RW file (e.g. 'ec.RW.flat')\n"
	"  -v, --ec_ver <FILE>            EC version file (e.g. 'ec.version')\n"
	"  -K, --keyset <PATH>            Keyset directory for re-signing\n"
	"  -h, --help                     Print this help message\n"
	"\n";

static void print_help(int argc, char *argv[]) { printf(usage, argv[0]); }

static bool read_le32_safe(const uint8_t *buf, uint32_t buf_size, uint32_t offset,
			   uint32_t *out)
{
	if (offset > buf_size || buf_size - offset < sizeof(uint32_t))
		return false;

	*out = le32toh(*(const uint32_t *)(buf + offset));
	return true;
}

static int truncate_ec_rw_buf(const uint8_t *buf, uint32_t buf_size, uint32_t *out_size)
{
	for (uint32_t offset = 0; offset <= MAX_COOKIE_SEARCH_OFFSET; offset += 4) {
		uint32_t cookie1 = 0, cookie2 = 0, size_dec = 0;

		if (!read_le32_safe(buf, buf_size, offset, &cookie1) ||
		    !read_le32_safe(buf, buf_size, offset + COOKIE2_OFFSET, &cookie2))
			break;
		if (cookie1 != COOKIE1_SIGNATURE || cookie2 != COOKIE2_SIGNATURE)
			continue;
		if (!read_le32_safe(buf, buf_size, offset + SIZE_OFFSET, &size_dec) ||
		    size_dec == 0 || size_dec > buf_size) {
			ERROR("Invalid image size: 0x%08x (%u).\n", size_dec, size_dec);
			return -1;
		}
		INFO("Found cookies at %u. Image size: 0x%08x (%u).\n", offset, size_dec,
		     size_dec);
		*out_size = size_dec;
		return 0;
	}

	ERROR("No image_data cookies found within %u bytes.\n", MAX_COOKIE_SEARCH_OFFSET);
	return -1;
}

static int extract_ecrw_from_ec(const char *ec_file, const char *ecrw_file,
				struct tempfile *tempfiles, const char **ec_ver)
{
	uint8_t *ec_buf = NULL;
	uint32_t ec_size = 0;
	FmapAreaHeader *ah = NULL;
	uint8_t *area_ptr;
	uint32_t ecrw_len = 0;
	int rv = -1;

	if (vb2_read_file(ec_file, &ec_buf, &ec_size) != VB2_SUCCESS) {
		ERROR("Failed to read EC file: %s\n", ec_file);
		return -1;
	}

	FmapHeader *fmap = fmap_find(ec_buf, ec_size);

	if (!fmap) {
		ERROR("No FMAP found in EC file: %s\n", ec_file);
		goto done;
	}

	area_ptr = fmap_find_by_name(ec_buf, ec_size, fmap, "RW_FW", &ah);
	if (area_ptr) {
		ecrw_len = ah->area_size;
	} else {
		INFO("Falling back to EC_RW section for legacy EC.\n");
		area_ptr = fmap_find_by_name(ec_buf, ec_size, fmap, "EC_RW", &ah);
		if (!area_ptr) {
			ERROR("Neither RW_FW nor EC_RW found in %s\n", ec_file);
			goto done;
		}
		if (truncate_ec_rw_buf(area_ptr, ah->area_size, &ecrw_len) != 0)
			goto done;
	}

	if (vb2_write_file(ecrw_file, area_ptr, ecrw_len) != VB2_SUCCESS) {
		ERROR("Failed to write extracted EC RW to %s\n", ecrw_file);
		goto done;
	}

	area_ptr = fmap_find_by_name(ec_buf, ec_size, fmap, "RW_FWID", &ah);
	if (area_ptr && ah->area_size > 0) {
		const char *ver_file = create_temp_file(tempfiles);

		if (!ver_file ||
		    vb2_write_file(ver_file, area_ptr, ah->area_size) != VB2_SUCCESS) {
			ERROR("Failed to write RW_FWID\n");
			goto done;
		}
		*ec_ver = ver_file;
	}

	rv = 0;
done:
	free(ec_buf);
	return rv;
}

static int extract_ecrw_from_ap(const char *ap_for_ec, const char *ecrw_file,
				struct tempfile *tempfiles, const char **ec_ver,
				const char **ec_config)
{
	const char *region = fmap_regions[0];

	if (cbfstool_extract(ap_for_ec, region, CBFS_ECRW_NAME, ecrw_file) != 0) {
		ERROR("Failed to extract %s from %s (%s)\n", CBFS_ECRW_NAME, ap_for_ec, region);
		return -1;
	}

	if (cbfstool_file_exists(ap_for_ec, region, CBFS_ECRW_VERSION_NAME)) {
		const char *ver_file = create_temp_file(tempfiles);

		if (!ver_file ||
		    cbfstool_extract(ap_for_ec, region, CBFS_ECRW_VERSION_NAME, ver_file) != 0)
			return -1;
		*ec_ver = ver_file;
	} else {
		WARN("%s not found in source AP file.\n", CBFS_ECRW_VERSION_NAME);
	}

	if (cbfstool_file_exists(ap_for_ec, region, CBFS_ECRW_CONFIG_NAME)) {
		const char *cfg_file = create_temp_file(tempfiles);

		if (!cfg_file ||
		    cbfstool_extract(ap_for_ec, region, CBFS_ECRW_CONFIG_NAME, cfg_file) != 0)
			return -1;
		*ec_config = cfg_file;
	} else {
		WARN("%s not found in source AP file.\n", CBFS_ECRW_CONFIG_NAME);
	}

	return 0;
}

static int do_swap_cbfs_file(int argc, char *argv[])
{
	const char *image = NULL;
	const char *ec = NULL;
	const char *ec_config = NULL;
	const char *ap_for_ec = NULL;
	const char *raw_ecrw = NULL;
	const char *ec_ver = NULL;
	const char *keyset = NULL;
	char *default_ec_config = NULL;
	int i;

	optind = 1;
	while ((i = getopt_long(argc, argv, "i:e:a:r:v:K:h", long_opts, NULL)) != -1) {
		switch (i) {
		case 'i':
			image = optarg;
			break;
		case 'e':
			ec = optarg;
			break;
		case OPT_EC_CONFIG:
			ec_config = optarg;
			break;
		case 'a':
			ap_for_ec = optarg;
			break;
		case 'r':
			raw_ecrw = optarg;
			break;
		case 'v':
			ec_ver = optarg;
			break;
		case 'K':
			keyset = optarg;
			break;
		case 'h':
			print_help(argc, argv);
			return 0;
		default:
			print_help(argc, argv);
			return 1;
		}
	}

	if (!image) {
		ERROR("-i or --image is required.\n");
		return 1;
	}

	int ec_sources = (ec != NULL) + (ap_for_ec != NULL) + (raw_ecrw != NULL);

	if (ec_sources != 1) {
		ERROR("Exactly one of -e/--ec, -a/--ap_for_ec, or "
		      "-r/--raw_ecrw is required.\n");
		return 1;
	}

	if (ap_for_ec && ec_config) {
		ERROR("-a/--ap_for_ec conflicts with --ec_config.\n");
		return 1;
	}
	if (ec && ec_ver) {
		ERROR("-e/--ec conflicts with --ec_ver.\n");
		return 1;
	}
	if (ap_for_ec && ec_ver) {
		ERROR("-a/--ap_for_ec conflicts with --ec_ver.\n");
		return 1;
	}

	if (ec_config && access(ec_config, R_OK) != 0) {
		ERROR("EC config file '%s' does not exist.\n", ec_config);
		return 1;
	}
	if (ec_ver && access(ec_ver, R_OK) != 0) {
		ERROR("EC version file '%s' does not exist.\n", ec_ver);
		return 1;
	}

	if (ec && !ec_config) {
		const char *slash = strrchr(ec, '/');

		if (slash)
			ASPRINTF(&default_ec_config, "%.*s/ec.config", (int)(slash - ec), ec);
		else
			default_ec_config = strdup("ec.config");
		if (access(default_ec_config, R_OK) == 0) {
			ec_config = default_ec_config;
			INFO("Using ec.config from %s\n", ec_config);
		}
	}

	struct tempfile tempfile_head = {0};
	uint8_t *ecrw_buf = NULL;
	uint32_t ecrw_size = 0;
	int rv = 1;

	const char *ecrw_file = raw_ecrw ? raw_ecrw : create_temp_file(&tempfile_head);
	const char *ecrw_hash_file = create_temp_file(&tempfile_head);

	if (!ecrw_file || !ecrw_hash_file)
		goto cleanup;

	if (ec && extract_ecrw_from_ec(ec, ecrw_file, &tempfile_head, &ec_ver) != 0)
		goto cleanup;
	if (ap_for_ec && extract_ecrw_from_ap(ap_for_ec, ecrw_file, &tempfile_head, &ec_ver,
					      &ec_config) != 0)
		goto cleanup;

	if (vb2_read_file(ecrw_file, &ecrw_buf, &ecrw_size) != VB2_SUCCESS) {
		ERROR("Failed to read EC RW file: %s\n", ecrw_file);
		goto cleanup;
	}

	struct vb2_hash hash;

	if (vb2_hash_calculate(false, ecrw_buf, ecrw_size, VB2_HASH_SHA256, &hash) !=
		    VB2_SUCCESS ||
	    vb2_write_file(ecrw_hash_file, hash.sha256, VB2_SHA256_DIGEST_SIZE) !=
		    VB2_SUCCESS) {
		ERROR("Failed to compute or write %s\n", ecrw_hash_file);
		goto cleanup;
	}

	for (size_t r = 0; r < ARRAY_SIZE(fmap_regions); r++) {
		const char *region = fmap_regions[r];
		char comp_type[32];

		cbfstool_get_compression(image, region, CBFS_ECRW_NAME, "lzma", comp_type,
					 sizeof(comp_type));

		if (cbfstool_remove_if_exists(image, region, CBFS_ECRW_NAME) != 0 ||
		    cbfstool_remove_if_exists(image, region, CBFS_ECRW_HASH_NAME) != 0 ||
		    cbfstool_remove_if_exists(image, region, CBFS_ECRW_VERSION_NAME) != 0 ||
		    cbfstool_remove_if_exists(image, region, CBFS_ECRW_CONFIG_NAME) != 0) {
			ERROR("Failed to remove old ecrw entries from %s\n", region);
			goto cleanup;
		}

		if (cbfstool_expand(image, region) != 0) {
			ERROR("Failed to expand %s\n", region);
			goto cleanup;
		}

		if (cbfstool_add_raw(image, region, comp_type, ecrw_file, CBFS_ECRW_NAME,
				     false) != 0 ||
		    cbfstool_add_raw(image, region, "none", ecrw_hash_file, CBFS_ECRW_HASH_NAME,
				     false) != 0) {
			ERROR("Failed to add ecrw/ecrw.hash to %s\n", region);
			goto cleanup;
		}

		if (ec_ver) {
			if (cbfstool_add_raw(image, region, "none", ec_ver,
					     CBFS_ECRW_VERSION_NAME, false) != 0) {
				ERROR("Failed to add %s to %s\n", CBFS_ECRW_VERSION_NAME,
				      region);
				goto cleanup;
			}
		} else {
			WARN("%s is missing from source file.\n", CBFS_ECRW_VERSION_NAME);
		}

		if (ec_config) {
			if (cbfstool_add_raw(image, region, comp_type, ec_config,
					     CBFS_ECRW_CONFIG_NAME, true) != 0) {
				ERROR("Failed to add %s to %s\n", CBFS_ECRW_CONFIG_NAME,
				      region);
				goto cleanup;
			}
		} else {
			WARN("%s is missing from source file.\n", CBFS_ECRW_CONFIG_NAME);
		}
	}

	sign_option.type = FILE_TYPE_BIOS_IMAGE;
	sign_option.keysetdir = keyset;
	if (load_keyset() != 0 || futil_file_type_sign(FILE_TYPE_BIOS_IMAGE, image) != 0) {
		ERROR("Failed to sign AP image %s\n", image);
		goto cleanup;
	}

	rv = 0;

cleanup:
	free(sign_option.signprivate);
	free(sign_option.keyblock);
	free(sign_option.kernel_subkey);
	sign_option.signprivate = NULL;
	sign_option.keyblock = NULL;
	sign_option.kernel_subkey = NULL;
	free(ecrw_buf);
	remove_all_temp_files(&tempfile_head);
	free(default_ec_config);
	return rv;
}

DECLARE_FUTIL_COMMAND(swap_cbfs_file, do_swap_cbfs_file, VBOOT_VERSION_ALL,
		      "Swap EC RW binary in CBFS of AP image");
