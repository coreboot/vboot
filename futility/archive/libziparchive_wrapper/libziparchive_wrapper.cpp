/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <ziparchive/zip_archive.h>
#include <ziparchive/zip_writer.h>

#include <cstdio>
#include <cstring>

#include "include/libziparchive_wrapper.h"

/*
 * Until the archive is opened, all fields except from `path` will be NULL.
 * When opened for reading, `reader` is set to an instance of ZipArchive.
 * When opened for writing, `writer` is set to an instance of ZipWriter, and `file` is the
 * opened archive file.
 */
struct libziparchive_handle {
	void *reader;
	void *writer;
	FILE *file;
	const char *path;
};

static int open_reader(struct libziparchive_handle *handle)
{
	if (handle->reader)
		return 0;
	if (handle->writer) {
		fprintf(stderr, "ERROR: libziparchive_wrapper: simultaneous reading and "
				"writing is not supported.\n");
		return LIBZIPARCHIVE_WRAPPER_FAILURE;
	}
	return OpenArchive(handle->path, (ZipArchiveHandle *)&handle->reader);
}

static int open_writer(struct libziparchive_handle *handle)
{
	if (handle->writer)
		return 0;
	if (handle->reader) {
		fprintf(stderr, "ERROR: libziparchive_wrapper: simultaneous reading and "
				"writing is not supported.\n");
		return LIBZIPARCHIVE_WRAPPER_FAILURE;
	}

	handle->file = fopen(handle->path, "wb");
	if (!handle->file) {
		fprintf(stderr, "ERROR: libziparchive_wrapper: failed to open %s for writing\n",
			handle->path);
		return LIBZIPARCHIVE_WRAPPER_FAILURE;
	}
	handle->writer = new ZipWriter(handle->file);
	if (!handle->writer) {
		fprintf(stderr, "ERROR: libziparchive_wrapper: failed to create zip writer\n");
		return LIBZIPARCHIVE_WRAPPER_FAILURE;
	}

	return 0;
}

struct libziparchive_handle *libziparchive_open(const char *filename)
{
	auto handle = new (struct libziparchive_handle);
	handle->reader = NULL;
	handle->writer = NULL;
	handle->file = NULL;
	handle->path = filename;

	return handle;
}

int libziparchive_close(struct libziparchive_handle *handle)
{
	int r = 0;

	if (!handle)
		return r;

	if (handle->reader) {
		CloseArchive((ZipArchiveHandle)handle->reader);
		handle->reader = NULL;
	}

	if (handle->writer) {
		auto writer = (ZipWriter *)handle->writer;
		r |= writer->Finish();
		delete writer;
		handle->writer = NULL;
	}

	if (handle->file) {
		r |= fclose(handle->file);
		handle->file = NULL;
	}

	return r;
}

struct libziparchive_entry *libziparchive_alloc_entry()
{
	return (struct libziparchive_entry *)(new ZipEntry64);
}

void libziparchive_release_entry(struct libziparchive_entry *entry)
{
	delete (ZipEntry64 *)entry;
}

int libziparchive_start_iteration(struct libziparchive_handle *handle,
				  struct libziparchive_cookie **cookie)
{
	int r = open_reader(handle);
	if (r)
		return r;
	return StartIteration((ZipArchiveHandle)handle->reader, (void **)cookie);
}

void libziparchive_stop_iteration(struct libziparchive_cookie *cookie)
{
	EndIteration((void *)cookie);
}

int libziparchive_next(struct libziparchive_cookie *cookie, struct libziparchive_entry *entry,
		       char **name)
{
	std::string entry_name;

	int r = Next(cookie, (ZipEntry64 *)entry, &entry_name);
	*name = strdup(entry_name.c_str());

	return r;
}

int libziparchive_find_entry(struct libziparchive_handle *handle, const char *name,
			     struct libziparchive_entry *entry)
{
	int r = open_reader(handle);
	if (r)
		return r;

	return FindEntry((ZipArchiveHandle)handle->reader, name, (ZipEntry64 *)entry);
}

int32_t libziparchive_get_mtime(struct libziparchive_entry *entry)
{
	return ((ZipEntry64 *)entry)->mod_time;
}

int libziparchive_extract_entry(struct libziparchive_handle *handle,
				struct libziparchive_entry *entry, uint8_t **data, size_t *size)
{
	int r = open_reader(handle);
	if (r)
		return r;

	auto reader = (ZipArchiveHandle)handle->reader;
	auto target = (ZipEntry64 *)entry;

	*size = target->uncompressed_length;
	*data = (uint8_t *)malloc(*size);

	return ExtractToMemory(reader, target, *data, *size);
}

int libziparchive_write_entry(struct libziparchive_handle *handle, const char *name,
			      uint8_t *data, size_t size, int32_t mtime)
{
	int r = open_writer(handle);
	if (r)
		return r;

	auto writer = (ZipWriter *)handle->writer;

	r |= writer->StartEntryWithTime(name, ZipWriter::kCompress | ZipWriter::kAlign32,
					mtime);
	r |= writer->WriteBytes(data, size);
	r |= writer->FinishEntry();

	return r;
}
