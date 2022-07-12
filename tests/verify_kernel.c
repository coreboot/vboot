/* Copyright (c) 2014 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Routines for verifying a kernel or disk image
 */

#include "2sysincludes.h"
#include "2api.h"
#include "2common.h"
#include "2misc.h"
#include "2nvstorage.h"
#include "2secdata.h"
#include "host_common.h"
#include "util_misc.h"
#include "vboot_api.h"

static uint8_t workbuf[VB2_KERNEL_WORKBUF_RECOMMENDED_SIZE]
	__attribute__((aligned(VB2_WORKBUF_ALIGN)));
static struct vb2_context *ctx;
static struct vb2_shared_data *sd;

static uint8_t *diskbuf;

static struct vb2_kernel_params params;
static struct vb2_disk_info disk_info;

vb2_error_t VbExDiskRead(vb2ex_disk_handle_t handle, uint64_t lba_start,
			 uint64_t lba_count, void *buffer)
{
	if (handle != (vb2ex_disk_handle_t)1)
		return VB2_ERROR_UNKNOWN;
	if (lba_start >= disk_info.streaming_lba_count)
		return VB2_ERROR_UNKNOWN;
	if (lba_start + lba_count > disk_info.streaming_lba_count)
		return VB2_ERROR_UNKNOWN;

	memcpy(buffer, diskbuf + lba_start * 512, lba_count * 512);
	return VB2_SUCCESS;
}

vb2_error_t VbExDiskWrite(vb2ex_disk_handle_t handle, uint64_t lba_start,
			  uint64_t lba_count, const void *buffer)
{
	if (handle != (vb2ex_disk_handle_t)1)
		return VB2_ERROR_UNKNOWN;
	if (lba_start >= disk_info.streaming_lba_count)
		return VB2_ERROR_UNKNOWN;
	if (lba_start + lba_count > disk_info.streaming_lba_count)
		return VB2_ERROR_UNKNOWN;

	memcpy(diskbuf + lba_start * 512, buffer, lba_count * 512);
	return VB2_SUCCESS;
}

static void print_help(const char *progname)
{
	printf("\nUsage: %s <disk_image> <kernel.vbpubk>\n\n",
	       progname);
}

int main(int argc, char *argv[])
{
	struct vb2_packed_key *kernkey;
	uint64_t disk_bytes = 0;
	vb2_error_t rv;

	if (argc < 3) {
		print_help(argv[0]);
		return 1;
	}

	/* Load disk file */
	/* TODO: is it better to mmap() in the long run? */
	diskbuf = ReadFile(argv[1], &disk_bytes);
	if (!diskbuf) {
		fprintf(stderr, "Can't read disk file %s\n", argv[1]);
		return 1;
	}

	/* Read public key */
	kernkey = vb2_read_packed_key(argv[2]);
	if (!kernkey) {
		fprintf(stderr, "Can't read key file %s\n", argv[2]);
		return 1;
	}

	/* Set up params */
	disk_info.handle = (vb2ex_disk_handle_t)1;
	disk_info.bytes_per_lba = 512;
	disk_info.streaming_lba_count = disk_bytes / 512;
	disk_info.lba_count = disk_info.streaming_lba_count;

	params.kernel_buffer_size = 16 * 1024 * 1024;
	params.kernel_buffer = malloc(params.kernel_buffer_size);
	if (!params.kernel_buffer) {
		fprintf(stderr, "Can't allocate kernel buffer\n");
		return 1;
	}

	/* TODO(chromium:441893): support dev-mode flag and external gpt flag */
	disk_info.flags = 0;

	if (vb2api_init(&workbuf, sizeof(workbuf), &ctx)) {
		fprintf(stderr, "Can't initialize workbuf\n");
		return 1;
	}
	sd = vb2_get_sd(ctx);

	/* Copy kernel subkey to workbuf */
	{
		struct vb2_workbuf wb;
		struct vb2_packed_key *dst;
		uint32_t kernkey_size = kernkey->key_offset + kernkey->key_size;
		vb2_workbuf_from_ctx(ctx, &wb);
		dst = vb2_workbuf_alloc(&wb, kernkey_size);
		memcpy(dst, kernkey, kernkey_size);
		vb2_set_workbuf_used(ctx, vb2_offset_of(sd, wb.buf));
		sd->kernel_key_offset = vb2_offset_of(sd, dst);
		sd->kernel_key_size = kernkey_size;
	}

	/*
	 * vb2api_load_kernel() cares only about VBNV_DEV_BOOT_SIGNED_ONLY, and
	 * only in dev mode.  So just use defaults for nv storage.
	 */
	vb2_nv_init(ctx);
	/* We need to init kernel secdata for
	 * VB2_SECDATA_KERNEL_FLAG_HWCRYPTO_ALLOWED.
	 */
	vb2api_secdata_kernel_create(ctx);
	vb2_secdata_kernel_init(ctx);

	/* Try loading kernel */
	rv = vb2api_load_kernel(ctx, &params, &disk_info);
	if (rv != VB2_SUCCESS) {
		fprintf(stderr, "vb2api_load_kernel() failed with code %d\n",
			rv);
		return 1;
	}

	printf("Found a good kernel.\n");
	printf("Partition number:   %u\n", params.partition_number);
	printf("Bootloader address: 0x%" PRIx64 "\n",
	       params.bootloader_address);

	/* TODO: print other things (partition GUID, shared_data) */

	printf("Yaay!\n");
	return 0;
}
