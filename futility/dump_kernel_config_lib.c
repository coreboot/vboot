/* Copyright 2012 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Exports the kernel commandline from a given partition/image.
 */

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#if !defined (__FreeBSD__) && !defined(__OpenBSD__)
#include <sys/sysmacros.h>
#endif
#include <sys/types.h>
#include <unistd.h>

#include "futility.h"
#include "host_common.h"
#include "kernel_blob.h"
#include "vboot_api.h"
#include "vboot_host.h"

static ssize_t ReadFully(int fd, void *buf, size_t count)
{
	ssize_t nr_read = 0;
	while (nr_read < count) {
		ssize_t to_read = count - nr_read;
		ssize_t chunk = read(fd, buf + nr_read, to_read);
		if (chunk < 0) {
			return -1;
		} else if (chunk == 0) {
			break;
		}
		nr_read += chunk;
	}
	return nr_read;
}

/* Skip the stream by calling ReadFully() many times. Return 0 on success. */
static int SkipWithRead(int fd, size_t count)
{
	char buf[1024];
	ssize_t nr_skipped = 0;
	while (nr_skipped < count) {
		ssize_t to_read = count - nr_skipped;
		if (to_read > sizeof(buf)) {
			to_read = sizeof(buf);
		}
		if (ReadFully(fd, buf, to_read) != to_read)
			return -1;
		nr_skipped += to_read;
	}
	return 0;
}

static char *FindKernelConfigFromStream(int fd,
					uint64_t kernel_body_load_address)
{
	struct vb2_keyblock keyblock;
	struct vb2_kernel_preamble preamble;
	uint32_t now = 0;
	uint32_t offset = 0;

	/* Skip the keyblock */
	if (ReadFully(fd, &keyblock, sizeof(keyblock)) != sizeof(keyblock)) {
		FATAL("not enough data to fill keyblock header\n");
		return NULL;
	}
	ssize_t to_skip = keyblock.keyblock_size - sizeof(keyblock);
	if (to_skip < 0 || SkipWithRead(fd, to_skip)) {
		FATAL("keyblock_size advances past the end of the blob\n");
		return NULL;
	}
	now += keyblock.keyblock_size;

	/* Open up the preamble */
	if (ReadFully(fd, &preamble, sizeof(preamble)) != sizeof(preamble)) {
		FATAL("not enough data to fill preamble\n");
		return NULL;
	}
	to_skip = preamble.preamble_size - sizeof(preamble);
	if (to_skip < 0 || SkipWithRead(fd, to_skip)) {
		FATAL("preamble_size advances past the end of the blob\n");
		return NULL;
	}
	now += preamble.preamble_size;

	/* Read body_load_address from preamble if no
	 * kernel_body_load_address */
	if (kernel_body_load_address == USE_PREAMBLE_LOAD_ADDR)
		kernel_body_load_address = preamble.body_load_address;

	/* The x86 kernels have a pointer to the kernel commandline in the
	 * zeropage table, but that's irrelevant for ARM. Both types keep the
	 * config blob in the same place, so just go find it. */
	offset = preamble.bootloader_address -
	    (kernel_body_load_address + CROS_PARAMS_SIZE +
	     CROS_CONFIG_SIZE) + now;
	to_skip = offset - now;
	if (to_skip < 0 || SkipWithRead(fd, to_skip)) {
		FATAL("params are outside of the memory blob: %x\n", offset);
		return NULL;
	}
	char *ret = malloc(CROS_CONFIG_SIZE);
	if (!ret) {
		FATAL("No memory\n");
		return NULL;
	}
	if (ReadFully(fd, ret, CROS_CONFIG_SIZE) != CROS_CONFIG_SIZE) {
		FATAL("Cannot read kernel config\n");
		free(ret);
		ret = NULL;
	}
	return ret;
}

char *FindKernelConfig(const char *infile, uint64_t kernel_body_load_address)
{
	char *newstr = NULL;

	int fd = open(infile, O_RDONLY | O_CLOEXEC
#if !defined(__FreeBSD__) && !defined(__OpenBSD__)
			| O_LARGEFILE
#endif
			);
	if (fd < 0) {
		FATAL("Cannot open %s\n", infile);
		return NULL;
	}

	newstr = FindKernelConfigFromStream(fd, kernel_body_load_address);

	close(fd);

	return newstr;
}
