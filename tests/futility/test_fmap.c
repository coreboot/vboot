/* Copyright 2026 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for FMAP parsing.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "common/tests.h"
#include "fmap.h"

#define BUF_SIZE 0x400
#define FMAP_OFFSET 0x100
#define TABLE_SIZE(n) (sizeof(FmapHeader) + (n) * sizeof(FmapAreaHeader))

static uint8_t buf[BUF_SIZE];

/* Write an FMAP with nareas area headers at offset; return the area table. */
static FmapAreaHeader *write_fmap(uint32_t offset, uint16_t nareas)
{
	FmapHeader *fmap = (FmapHeader *)(buf + offset);
	FmapAreaHeader *ah = (FmapAreaHeader *)(fmap + 1);
	uint16_t i;

	memset(buf, 0, sizeof(buf));
	memcpy(fmap->fmap_signature, FMAP_SIGNATURE, FMAP_SIGNATURE_SIZE);
	fmap->fmap_ver_major = FMAP_VER_MAJOR;
	fmap->fmap_size = BUF_SIZE;
	fmap->fmap_nareas = nareas;
	for (i = 0; i < nareas && TABLE_SIZE(i + 1) <= BUF_SIZE - offset; i++)
		snprintf(ah[i].area_name, FMAP_NAMELEN, "AREA%u", i);
	return ah;
}

static void fmap_find_tests(void)
{
	const uint16_t max_nareas = (BUF_SIZE - FMAP_OFFSET - sizeof(FmapHeader)) /
				    sizeof(FmapAreaHeader);

	write_fmap(0, 2);
	TEST_PTR_EQ(fmap_find(buf, BUF_SIZE), buf, "FMAP at start");
	TEST_PTR_EQ(fmap_find(buf, TABLE_SIZE(2)), buf, "FMAP at start, exact fit");
	TEST_PTR_EQ(fmap_find(buf, TABLE_SIZE(2) - 1), NULL,
		    "FMAP at start, area table truncated");
	TEST_PTR_EQ(fmap_find(buf, sizeof(FmapHeader) - 1), NULL,
		    "Buffer smaller than FMAP header");

	write_fmap(FMAP_OFFSET, max_nareas);
	TEST_PTR_EQ(fmap_find(buf, BUF_SIZE), buf + FMAP_OFFSET,
		    "FMAP found by search, area table fits");

	write_fmap(FMAP_OFFSET, max_nareas + 1);
	TEST_PTR_EQ(fmap_find(buf, BUF_SIZE), NULL,
		    "FMAP found by search, area table truncated");

	write_fmap(FMAP_OFFSET, UINT16_MAX);
	TEST_PTR_EQ(fmap_find(buf, BUF_SIZE), NULL,
		    "FMAP found by search, too many areas");
}

static void fmap_find_by_name_tests(void)
{
	FmapAreaHeader *ah, *found;

	ah = write_fmap(0, 2);
	ah[0].area_offset = 0x200;
	ah[0].area_size = 0x100;
	ah[1].area_offset = BUF_SIZE;
	ah[1].area_size = 0;

	found = NULL;
	TEST_PTR_EQ(fmap_find_by_name(buf, BUF_SIZE, NULL, "AREA0", &found), buf + 0x200,
		    "Area within buffer");
	TEST_PTR_EQ(found, &ah[0], "Area within buffer, area header");
	TEST_PTR_EQ(fmap_find_by_name(buf, BUF_SIZE, NULL, "AREA1", NULL), buf + BUF_SIZE,
		    "Empty area at end of buffer");
	TEST_PTR_EQ(fmap_find_by_name(buf, BUF_SIZE, NULL, "NONE", NULL), NULL,
		    "Area not found");

	ah[0].area_size = BUF_SIZE - 0x200;
	TEST_PTR_EQ(fmap_find_by_name(buf, BUF_SIZE, NULL, "AREA0", NULL), buf + 0x200,
		    "Area ends at end of buffer");

	ah[0].area_size = BUF_SIZE - 0x200 + 1;
	found = NULL;
	TEST_PTR_EQ(fmap_find_by_name(buf, BUF_SIZE, NULL, "AREA0", &found), NULL,
		    "Area extends past end of buffer");
	TEST_PTR_EQ(found, NULL, "Area extends past end of buffer, area header");

	ah[0].area_size = UINT32_MAX - 0x100;
	TEST_PTR_EQ(fmap_find_by_name(buf, BUF_SIZE, NULL, "AREA0", NULL), NULL,
		    "Area offset + size overflows");

	ah[1].area_offset = BUF_SIZE + 1;
	TEST_PTR_EQ(fmap_find_by_name(buf, BUF_SIZE, NULL, "AREA1", NULL), NULL,
		    "Empty area past end of buffer");

	ah[1].area_offset = UINT32_MAX;
	TEST_PTR_EQ(fmap_find_by_name(buf, BUF_SIZE, NULL, "AREA1", NULL), NULL,
		    "Area offset at UINT32_MAX");
}

int main(int argc, char *argv[])
{
	fmap_find_tests();
	fmap_find_by_name_tests();

	return !gTestSuccess;
}
