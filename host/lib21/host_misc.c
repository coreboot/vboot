/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Host functions for verified boot.
 */

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "2common.h"
#include "2sha.h"
#include "2sysincludes.h"
#include "host_common.h"
#include "host_common21.h"
#include "host_misc21.h"

vb2_error_t vb2_read_file(const char *filename, uint8_t **data_ptr,
			  uint32_t *size_ptr)
{
	FILE *f;
	uint8_t *buf;
	long size;

	*data_ptr = NULL;
	*size_ptr = 0;

	f = fopen(filename, "rb");
	if (!f) {
		VB2_DEBUG("Unable to open file %s\n", filename);
		return VB2_ERROR_READ_FILE_OPEN;
	}

	fseek(f, 0, SEEK_END);
	size = ftell(f);
	rewind(f);

	if (size < 0 || size > UINT32_MAX) {
		fclose(f);
		return VB2_ERROR_READ_FILE_SIZE;
	}

	buf = malloc(size + 1);
	if (!buf) {
		fclose(f);
		return VB2_ERROR_READ_FILE_ALLOC;
	}
	buf[size] = '\0';

	if (size && 1 != fread(buf, size, 1, f)) {
		VB2_DEBUG("Unable to read file %s\n", filename);
		fclose(f);
		free(buf);
		return VB2_ERROR_READ_FILE_DATA;
	}

	fclose(f);

	*data_ptr = buf;
	*size_ptr = size;
	return VB2_SUCCESS;
}

vb2_error_t vb2_write_file(const char *filename, const void *buf, uint32_t size)
{
	FILE *f = fopen(filename, "wb");

	if (!f) {
		VB2_DEBUG("Unable to open file %s\n", filename);
		return VB2_ERROR_WRITE_FILE_OPEN;
	}

	if (size && 1 != fwrite(buf, size, 1, f)) {
		VB2_DEBUG("Unable to write to file %s\n", filename);
		fclose(f);
		unlink(filename);  /* Delete any partial file */
		return VB2_ERROR_WRITE_FILE_DATA;
	}

	fclose(f);
	return VB2_SUCCESS;
}

vb2_error_t vb2_write_temp_file(const uint8_t *data, uint32_t data_size,
				char **path_out)
{
	int fd;
	ssize_t write_rv;
	vb2_error_t rv;
	char *path;
	mode_t umask_save;

	*path_out = NULL;

	path = strdup(VBOOT_TMP_DIR "/vb2_tempfile.XXXXXX");
	if (!path)
		return VB2_ERROR_WRITE_FILE_OPEN;

	/* Set the umask before mkstemp for security considerations. */
	umask_save = umask(077);
	fd = mkstemp(path);
	umask(umask_save);
	if (fd < 0) {
		rv = VB2_ERROR_WRITE_FILE_OPEN;
		goto fail;
	}

	while (data && data_size > 0) {
		write_rv = write(fd, data, data_size);
		if (write_rv < 0) {
			close(fd);
			unlink(path);
			rv = VB2_ERROR_WRITE_FILE_DATA;
			goto fail;
		}

		data_size -= write_rv;
		data += write_rv;
	}

	close(fd);
	*path_out = path;
	return VB2_SUCCESS;

fail:
	free(path);
	return rv;
}

vb2_error_t vb21_write_object(const char *filename, const void *buf)
{
	const struct vb21_struct_common *cptr = buf;

	return vb2_write_file(filename, buf, cptr->total_size);
}

uint32_t vb2_desc_size(const char *desc)
{
	if (!desc || !*desc)
		return 0;

	return roundup32(strlen(desc) + 1);
}

vb2_error_t vb2_str_to_id(const char *str, struct vb2_id *id)
{
	uint8_t val = 0, nib;
	size_t n;

	if (!str)
		return VB2_ERROR_STR_TO_ID;

	memset(id, 0, sizeof(*id));

	for (n = 0; n < 2 * VB2_ID_NUM_BYTES; n++, str++) {
		while (*str && !isxdigit(*str))
			str++;
		if (sscanf(str, "%1hhx", &nib) != 1)
			break;
		if (n & 1)
			id->raw[n / 2] = val | nib;
		else
			val = nib << 4;
	}

	/* If we get at least one valid byte, that's good enough. */
	return n >= 2 ? VB2_SUCCESS : VB2_ERROR_STR_TO_ID;
}
