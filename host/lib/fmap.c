/* Copyright 2011 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "fmap.h"

/* Check for a valid FMAP header and area table within avail bytes at ptr */
static int is_fmap(uint8_t *ptr, size_t avail)
{
	FmapHeader *fmap_header = (FmapHeader *)ptr;

	if (avail < sizeof(FmapHeader))
		return 0;

	if (0 != memcmp(ptr, FMAP_SIGNATURE, FMAP_SIGNATURE_SIZE))
		return 0;

	if (fmap_header->fmap_ver_major != FMAP_VER_MAJOR) {
		fprintf(stderr, "Found FMAP, but major version is %u instead of %u\n",
			fmap_header->fmap_ver_major, FMAP_VER_MAJOR);
		return 0;
	}

	if (fmap_header->fmap_nareas >
	    (avail - sizeof(FmapHeader)) / sizeof(FmapAreaHeader)) {
		fprintf(stderr, "Found FMAP, but its %u areas exceed the buffer\n",
			fmap_header->fmap_nareas);
		return 0;
	}

	return 1;
}

/* Find and point to the FMAP header within the buffer */
FmapHeader *fmap_find(uint8_t *ptr, size_t size)
{
	ssize_t offset, align;
	ssize_t lim = size - sizeof(FmapHeader);

	if (lim >= 0 && is_fmap(ptr, size))
		return (FmapHeader *)ptr;

	/* Search large alignments before small ones to find "right" FMAP. */
	for (align = FMAP_SEARCH_STRIDE; align <= lim; align *= 2);
	for (; align >= FMAP_SEARCH_STRIDE; align /= 2)
		for (offset = align; offset <= lim; offset += align * 2)
			if (is_fmap(ptr + offset, size - offset))
				return (FmapHeader *)(ptr + offset);

	return NULL;
}

/*
 * Search for an area by name, return pointer to its beginning. Return NULL if
 * the area does not lie entirely within the buffer.
 */
uint8_t *fmap_find_by_name(uint8_t *ptr, size_t size, FmapHeader *fmap,
			   const char *name, FmapAreaHeader **ah_ptr)
{
	int i;
	FmapAreaHeader *ah;

	if (!fmap)
		fmap = fmap_find(ptr, size);
	if (!fmap)
		return NULL;

	ah = (FmapAreaHeader*)((void *)fmap + sizeof(FmapHeader));
	for (i = 0; i < fmap->fmap_nareas; i++)
		if (!strncmp(ah[i].area_name, name, FMAP_NAMELEN)) {
			if (ah[i].area_offset > size ||
			    ah[i].area_size > size - ah[i].area_offset)
				return NULL;
			if (ah_ptr)
				*ah_ptr = ah + i;
			return ptr + ah[i].area_offset;
		}

	return NULL;
}
