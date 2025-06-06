/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <assert.h>
#include <string.h>

#include "futility.h"
#include "updater_archive.h"

#if !defined(HAVE_LIBZIP)
#error This file requires libzip
#endif

#ifndef __clang__
/* If libzip headers were built for Clang but later get included with GCC you
   need this. This check should really be in libzip but apparently they think
   it's fine to ship compiler-specific system headers or something... */
#define _Nullable
#define _Nonnull
#endif
#include <zip.h>

/*
 * -- The libzip driver (for ZIP, the official format for CrOS fw updater). --
 */

/* Callback for archive_open on a ZIP file. */
static void *archive_zip_open(const char *name)
{
	return zip_open(name, 0, NULL);
}

/* Callback for archive_close on a ZIP file. */
static int archive_zip_close(void *handle)
{
	struct zip *zip = (struct zip *)handle;

	if (zip)
		return zip_close(zip);
	return 0;
}

/* Callback for archive_has_entry on a ZIP file. */
static int archive_zip_has_entry(void *handle, const char *fname)
{
	struct zip *zip = (struct zip *)handle;
	assert(zip);
	return zip_name_locate(zip, fname, 0) != -1;
}

/* Callback for archive_walk on a ZIP file. */
static int archive_zip_walk(
		void *handle, void *arg,
		int (*callback)(const char *name, void *arg))
{
	zip_int64_t num, i;
	struct zip *zip = (struct zip *)handle;
	assert(zip);

	num = zip_get_num_entries(zip, 0);
	if (num < 0)
		return 1;
	for (i = 0; i < num; i++) {
		const char *name = zip_get_name(zip, i, 0);
		if (*name && name[strlen(name) - 1] == '/')
			continue;
		if (callback(name, arg))
			break;
	}
	return 0;
}

/* Callback for archive_zip_read_file on a ZIP file. */
static int archive_zip_read_file(void *handle, const char *fname,
			     uint8_t **data, uint32_t *size, int64_t *mtime)
{
	struct zip *zip = (struct zip *)handle;
	struct zip_file *fp;
	struct zip_stat stat;

	assert(zip);
	*data = NULL;
	*size = 0;
	zip_stat_init(&stat);
	if (zip_stat(zip, fname, 0, &stat)) {
		ERROR("Fail to stat entry in ZIP: %s\n", fname);
		return 1;
	}
	fp = zip_fopen(zip, fname, 0);
	if (!fp) {
		ERROR("Failed to open entry in ZIP: %s\n", fname);
		return 1;
	}
	*data = (uint8_t *)malloc(stat.size + 1);
	if (*data) {
		if (zip_fread(fp, *data, stat.size) == stat.size) {
			if (mtime)
				*mtime = stat.mtime;
			*size = stat.size;
			(*data)[stat.size] = '\0';
		} else {
			ERROR("Failed to read entry in zip: %s\n", fname);
			free(*data);
			*data = NULL;
		}
	}
	zip_fclose(fp);
	return *data == NULL;
}

/* Callback for archive_zip_write_file on a ZIP file. */
static int archive_zip_write_file(void *handle, const char *fname,
				  uint8_t *data, uint32_t size, int64_t mtime)
{
	struct zip *zip = (struct zip *)handle;
	struct zip_source *src;

	VB2_DEBUG("Writing %s\n", fname);
	assert(zip);
	src = zip_source_buffer(zip, data, size, 0);
	if (!src) {
		ERROR("Internal error: cannot allocate buffer: %s\n", fname);
		return 1;
	}

	if (zip_file_add(zip, fname, src, ZIP_FL_OVERWRITE) < 0) {
		zip_source_free(src);
		ERROR("Internal error: failed to add: %s\n", fname);
		return 1;
	}
	/* zip_source_free is not needed if zip_file_add success. */
#if LIBZIP_VERSION_MAJOR >= 1
	zip_file_set_mtime(zip, zip_name_locate(zip, fname, 0), mtime, 0);
#endif
	return 0;
}

struct u_archive archive_zip = {
	.open = archive_zip_open,
	.close = archive_zip_close,
	.walk = archive_zip_walk,
	.has_entry = archive_zip_has_entry,
	.read_file = archive_zip_read_file,
	.write_file = archive_zip_write_file,
};
