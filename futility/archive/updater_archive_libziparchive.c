/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifdef HAVE_LIBZIPARCHIVE

#include "futility.h"
#include "updater_archive.h"
#include "libziparchive_wrapper.h"

/*
 * -- The libziparchive driver (using wrapper). --
 */

/* Callback for archive_open on a ZIP file. */
static void *archive_libziparchive_open(const char *name)
{
	return libziparchive_open(name);
}

/* Callback for archive_close on a ZIP file. */
static int archive_libziparchive_close(void *handle)
{
	if (!handle)
		return 0;
	return libziparchive_close((struct libziparchive_handle *)handle);
}

/* Callback for archive_has_entry on a ZIP file. */
static int archive_libziparchive_has_entry(void *handle, const char *fname)
{
	struct libziparchive_entry *entry = libziparchive_alloc_entry();
	int r = libziparchive_find_entry(handle, fname, entry);
	libziparchive_release_entry(entry);
	return !r;
}

/* Callback for archive_walk on a ZIP file. */
static int archive_libziparchive_walk(void *handle, void *arg,
				      int (*callback)(const char *name, void *arg))
{
	struct libziparchive_handle *reader = (struct libziparchive_handle *)handle;
	struct libziparchive_cookie *cookie;

	if (libziparchive_start_iteration(reader, &cookie)) {
		fprintf(stderr,
			"ERROR: Failed to start iteration over files in the archive.\n");
		return LIBZIPARCHIVE_WRAPPER_FAILURE;
	}

	struct libziparchive_entry *entry = libziparchive_alloc_entry();
	char *name;
	int r = 0;

	while (r != LIBZIPARCHIVE_ITERATION_END) {
		r = libziparchive_next(cookie, entry, &name);

		if (r < LIBZIPARCHIVE_ITERATION_END) {
			fprintf(stderr,
				"ERROR: Failed while iterating over files in the archive.\n");
			free(name);
			break;
		} else if (r == 0 && name[strlen(name) - 1] != '/') {
			if (callback(name, arg)) {
				r = LIBZIPARCHIVE_ITERATION_END;
				free(name);
				break;
			}
		}

		free(name);
	}

	if (r == LIBZIPARCHIVE_ITERATION_END)
		r = 0;

	libziparchive_stop_iteration(cookie);
	libziparchive_release_entry(entry);

	return r;
}

/* Callback for archive_zip_read_file on a ZIP file. */
static int archive_libziparchive_read_file(void *handle, const char *fname, uint8_t **data,
					   uint32_t *size, int64_t *mtime)
{
	struct libziparchive_entry *entry = libziparchive_alloc_entry();
	if (libziparchive_find_entry(handle, fname, entry)) {
		fprintf(stderr, "ERROR: Failed to locate %s in the archive.\n", fname);
		libziparchive_release_entry(entry);
		return LIBZIPARCHIVE_WRAPPER_FAILURE;
	}

	size_t size64;
	if (libziparchive_extract_entry(handle, entry, data, &size64)) {
		fprintf(stderr, "ERROR: Failed to extract %s from the archive.\n", fname);
		libziparchive_release_entry(entry);
		return LIBZIPARCHIVE_WRAPPER_FAILURE;
	}
	*size = size64;

	if (mtime)
		*mtime = libziparchive_get_mtime(entry);

	libziparchive_release_entry(entry);

	return 0;
}

/* Callback for archive_zip_write_file on a ZIP file. */
static int archive_libziparchive_write_file(void *handle, const char *fname, uint8_t *data,
					    uint32_t size, int64_t mtime)
{
	return libziparchive_write_entry(handle, fname, data, size, mtime);
}

struct u_archive archive_libziparchive = {
	.open = archive_libziparchive_open,
	.close = archive_libziparchive_close,
	.walk = archive_libziparchive_walk,
	.has_entry = archive_libziparchive_has_entry,
	.read_file = archive_libziparchive_read_file,
	.write_file = archive_libziparchive_write_file,
};

#endif
