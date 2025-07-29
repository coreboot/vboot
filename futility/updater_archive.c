/* Copyright 2018 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Accessing updater resources from an archive.
 */

#include <assert.h>
#include <sys/stat.h>
#if defined(__OpenBSD__)
#include <sys/types.h>
#endif
#include <unistd.h>

#include "updater.h"
#include "archive/updater_archive.h"

/*
 * -- The public functions for using u_archive. --
 */

struct u_archive *archive_open(const char *path)
{
	struct stat path_stat;
	struct u_archive *ar;
	void *handle;

	if (stat(path, &path_stat) != 0) {
		ERROR("Cannot identify type of path: %s\n", path);
		return NULL;
	}

	ar = (struct u_archive *)calloc(sizeof(*ar), 1);
	if (!ar) {
		ERROR("Internal error: allocation failure.\n");
		return NULL;
	}

	if (S_ISDIR(path_stat.st_mode)) {
		VB2_DEBUG("Found directory, use fallback (fs) driver: %s\n",
			  path);
		/* Regular file system. */
		*ar = archive_fallback;
	}

	/* Format detection must try ZIP (the official format) first. */
#ifdef HAVE_LIBZIP
	if (!ar->open) {
		handle = archive_zip.open(path);
		if (handle) {
			VB2_DEBUG("Found a ZIP file: %s\n", path);
			*ar = archive_zip;
			ar->handle = handle;
		}
	}
#endif

#ifdef HAVE_LIBZIPARCHIVE
	if (!ar->open) {
		handle = archive_libziparchive.open(path);
		if (handle) {
			VB2_DEBUG("Found a file, use libziparchive: %s\n", path);
			*ar = archive_libziparchive;
			ar->handle = handle;
		}
	}
#endif

	/* LIBARCHIVE must be the last driver. */
#ifdef HAVE_LIBARCHIVE
	if (!ar->open) {
		handle = archive_libarchive.open(path);
		if (handle) {
			VB2_DEBUG("Found a file, use libarchive: %s\n", path);
			*ar = archive_libarchive;
			ar->handle = handle;
		}
	}
#endif

	if (!ar->open) {
		ERROR("Found a file, but no drivers were selected: %s\n", path);
		free(ar);
		return NULL;
	}

	/* Some drivers may have already opened the archive. */
	if (!ar->handle)
		ar->handle = ar->open(path);

	if (!ar->handle) {
		ERROR("Failed to open archive: %s\n", path);
		free(ar);
		return NULL;
	}
	return ar;
}

int archive_close(struct u_archive *ar)
{
	int r = ar->close(ar->handle);
	free(ar);
	return r;
}

int archive_has_entry(struct u_archive *ar, const char *name)
{
	if (!ar || *name == '/')
		return archive_fallback.has_entry(NULL, name);
	return ar->has_entry(ar->handle, name);
}

int archive_walk(struct u_archive *ar, void *arg,
		 int (*callback)(const char *path, void *arg))
{
	if (!ar)
		return archive_fallback.walk(NULL, arg, callback);
	return ar->walk(ar->handle, arg, callback);
}

int archive_read_file(struct u_archive *ar, const char *fname,
		      uint8_t **data, uint32_t *size, int64_t *mtime)
{
	if (!ar || *fname == '/')
		return archive_fallback.read_file(NULL, fname, data, size, mtime);
	return ar->read_file(ar->handle, fname, data, size, mtime);
}

int archive_write_file(struct u_archive *ar, const char *fname,
		       uint8_t *data, uint32_t size, int64_t mtime)
{
	if (!ar || *fname == '/')
		return archive_fallback.write_file(NULL, fname, data, size, mtime);
	return ar->write_file(ar->handle, fname, data, size, mtime);
}

struct _copy_arg {
	struct u_archive *from, *to;
};

/* Callback for archive_copy. */
static int archive_copy_callback(const char *path, void *_arg)
{
	const struct _copy_arg *arg = (const struct _copy_arg*)_arg;
	uint32_t size;
	uint8_t *data;
	int64_t mtime;
	int r;

	INFO("Copying: %s\n", path);
	if (archive_read_file(arg->from, path, &data, &size, &mtime)) {
		ERROR("Failed reading: %s\n", path);
		return 1;
	}
	r = archive_write_file(arg->to, path, data, size, mtime);
	VB2_DEBUG("result=%d\n", r);
	free(data);
	return r;
}

int archive_copy(struct u_archive *from, struct u_archive *to)
{
	struct _copy_arg arg = { .from = from, .to = to };
	return archive_walk(from, &arg, archive_copy_callback);
}
