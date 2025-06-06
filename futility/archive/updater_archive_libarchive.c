/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include <archive.h>
#include <archive_entry.h>

#include "futility.h"
#include "updater_archive.h"

#if !defined(HAVE_LIBARCHIVE)
# error This file requires libarchive
#endif

/*
 * -- The cache driver (used by other drivers). --
 */

/*
 * For stream-based archives (e.g., tar+gz) we want to create a cache for
 * storing the names and contents for later processing.
 */
struct archive_cache {
	char *name;
	uint8_t *data;
	int64_t mtime;
	size_t size;
	int has_data;
	struct archive_cache *next;
};

/* Add a new cache node to an existing cache list and return the new head. */
static struct archive_cache *archive_cache_new(struct archive_cache *cache,
					       const char *name)
{
	struct archive_cache *c;

	c = (struct archive_cache *)calloc(sizeof(*c), 1);
	if (!c)
		return NULL;

	c->name = strdup(name);
	if (!c->name) {
		free(c);
		return NULL;
	}

	c->next = cache;
	return c;
}

/* Find and return an entry (by name) from the cache. */
static struct archive_cache *archive_cache_find(struct archive_cache *c,
						const char *name)
{
	for (; c; c = c->next) {
		assert(c->name);
		if (!strcmp(c->name, name))
			return c;
	}
	return NULL;
}

/* Callback for archive_walk to process all entries in the cache. */
static int archive_cache_walk(
		struct archive_cache *c, void *arg,
		int (*callback)(const char *name, void *arg))
{
	for (; c; c = c->next) {
		assert(c->name);
		if (callback(c->name, arg))
			break;
	}
	return 0;
}

/* Delete all entries in the cache. */
static void *archive_cache_free(struct archive_cache *c)
{
	struct archive_cache *next;

	while (c) {
		next = c->next;
		free(c->name);
		free(c->data);
		free(c);
		c = next;
	}
	return NULL;
}

/*
 * -- The libarchive driver (multiple formats but very slow). --
 */

enum {
	FILTER_IGNORE,
	FILTER_ABORT,
	FILTER_NAME_ONLY,
	FILTER_READ_ALL,
};

static struct archive_cache *libarchive_read_file_entries(
		const char *fpath, int (*filter)(struct archive_entry *entry))
{
	struct archive *a = archive_read_new();
	struct archive_entry *entry;
	struct archive_cache *c, *cache = NULL;
	int r;

	assert(a);
	archive_read_support_filter_all(a);
	archive_read_support_format_all(a);
	r = archive_read_open_filename(a, fpath, 10240);
	if (r != ARCHIVE_OK) {
		ERROR("Failed parsing archive using libarchive: %s\n", fpath);
		archive_read_free(a);
		return NULL;
	}

	WARN("Loading data from archive: %s ", fpath);
	while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
		fputc('.', stderr);
		if (archive_entry_filetype(entry) != AE_IFREG)
			continue;
		if (filter)
			r = filter(entry);
		else
			r = FILTER_READ_ALL;

		if (r == FILTER_ABORT)
			break;
		if (r == FILTER_IGNORE)
			continue;

		c = archive_cache_new(cache, archive_entry_pathname(entry));
		if (!c) {
			ERROR("Internal error: out of memory.\n");
			archive_cache_free(cache);
			archive_read_free(a);
			return NULL;
		}
		cache = c;

		if (r == FILTER_NAME_ONLY)
			continue;

		assert(r == FILTER_READ_ALL);
		c->size = archive_entry_size(entry);
		c->mtime = archive_entry_mtime(entry);
		c->data = (uint8_t *)calloc(1, c->size + 1);
		if (!c->data) {
			WARN("Out of memory when loading: %s\n", c->name);
			continue;
		}
		if (archive_read_data(a, c->data, c->size) != c->size) {
			WARN("Failed reading from archive: %s\n", c->name);
			continue;
		}
		c->has_data = 1;
	}
	fputs("\r\n", stderr);  /* Flush the '.' */
	VB2_DEBUG("Finished loading from archive: %s.\n", fpath);

	archive_read_free(a);
	return cache;
}

/* Callback for archive_open on an ARCHIVE file. */
static void *archive_libarchive_open(const char *name)
{
	/*
	 * The firmware archives today can usually all load into memory
	 * so we are using a NULL filter. Change that to a specific list in
	 * future if the /build/$BOARD/firmware archive becomes too large.
	 */
	return libarchive_read_file_entries(name, NULL);
}

/* Callback for archive_close on an ARCHIVE file. */
static int archive_libarchive_close(void *handle)
{
	archive_cache_free(handle);
	return 0;
}

/* Callback for archive_has_entry on an ARCHIVE file. */
static int archive_libarchive_has_entry(void *handle, const char *fname)
{
	return archive_cache_find(handle, fname) != NULL;
}

/* Callback for archive_walk on an ARCHIVE file. */
static int archive_libarchive_walk(
		void *handle, void *arg,
		int (*callback)(const char *name, void *arg))
{
	return archive_cache_walk(handle, arg, callback);
}

/* Callback for archive_read_file on an ARCHIVE file. */
static int archive_libarchive_read_file(
		void *handle, const char *fname, uint8_t **data,
		uint32_t *size, int64_t *mtime)
{
	struct archive_cache *c = archive_cache_find(handle, fname);

	if (!c)
		return 1;

	if (!c->has_data) {
		/* TODO(hungte) Re-read. */
		ERROR("Not in the cache: %s\n", fname);
		return 1;
	}

	if (mtime)
		*mtime = c->mtime;
	if (size)
		*size = c->size;
	*data = (uint8_t *)malloc(c->size + 1);
	if (!*data) {
		ERROR("Out of memory when reading: %s\n", c->name);
		return 1;
	}
	memcpy(*data, c->data, c->size);
	(*data)[c->size] = '\0';
	return 0;
}

/* Callback for archive_write_file on an ARCHIVE file. */
static int archive_libarchive_write_file(
		void *handle, const char *fname, uint8_t *data, uint32_t size,
		int64_t mtime)
{
	ERROR("Not implemented!\n");
	return 1;
}

struct u_archive archive_libarchive = {
	.open = archive_libarchive_open,
	.close = archive_libarchive_close,
	.walk = archive_libarchive_walk,
	.has_entry = archive_libarchive_has_entry,
	.read_file = archive_libarchive_read_file,
	.write_file = archive_libarchive_write_file,
};
