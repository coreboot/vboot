/* Copyright 2025 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef VBOOT_REFERENCE_CGPTLIB_H_
#define VBOOT_REFERENCE_CGPTLIB_H_

#include "../2lib/include/2sysincludes.h"
#include "gpt_misc.h"

enum GptPartition {
	GPT_ANDROID_BOOT = 0,
	GPT_ANDROID_VENDOR_BOOT,
	GPT_ANDROID_INIT_BOOT,
	GPT_ANDROID_PVMFW,
	GPT_ANDROID_PRELOADED_NUM,

	/* Partitions below this point do not get preloaded */
	GPT_ANDROID_MISC = GPT_ANDROID_PRELOADED_NUM,
	GPT_ANDROID_VBMETA,
};

extern const char *GptPartitionNames[];

/**
 * Initializes the GPT data structure's internal state.
 *
 * The following fields must be filled before calling this function:
 *
 *   primary_header
 *   secondary_header
 *   primary_entries
 *   secondary_entries
 *   sector_bytes
 *   drive_sectors
 *   stored_on_device
 *   gpt_device_sectors
 *
 * On return the modified field may be set, if the GPT data has been modified
 * and should be written to disk.
 *
 * Returns GPT_SUCCESS if successful, non-zero if error:
 *   GPT_ERROR_INVALID_HEADERS, both partition table headers are invalid, enters
 *                              recovery mode,
 *   GPT_ERROR_INVALID_ENTRIES, both partition table entries are invalid, enters
 *                              recovery mode,
 *   GPT_ERROR_INVALID_SECTOR_SIZE, size of a sector is not supported,
 *   GPT_ERROR_INVALID_SECTOR_NUMBER, number of sectors in drive is invalid (too
 *                                    small) */
int GptInit(GptData *gpt);

/**
 * Return the nth instance of partition entry matching the partition type guid
 * from the gpt table. Instance value starts from 0. If the entry is not found,
 * it returns NULL.
 */
GptEntry *GptFindNthEntry(GptData *gpt, const Guid *guid, unsigned int n);

/**
 * Updates the kernel entry with the specified index, using the specified type
 * of update (GPT_UPDATE_ENTRY_*).
 *
 * On return the modified field may be set, if the GPT data has been modified
 * and should be written to disk.
 *
 * Returns GPT_SUCCESS if successful, else
 *   GPT_ERROR_INVALID_UPDATE_TYPE, invalid 'update_type' is given.
 */
int GptUpdateKernelWithEntry(GptData *gpt, GptEntry *e, uint32_t update_type);

/**
 * Updates the kernel entry identified by current_kernel field. If
 * current_kernel is not set it returns an error.
 *
 * Returns GPT_SUCCESS if successful, else
 *   GPT_ERROR_INVALID_UPDATE_TYPE, invalid 'update_type' is given.
 */
int GptUpdateKernelEntry(GptData *gpt, uint32_t update_type);

/**
 * Provides the location of the next bootable partition, in order of decreasing
 * priority.
 *
 * On return gpt.current_kernel contains the partition index of the current
 * bootable partition.
 *
 * Returns gpt entry of partition to boot if successful, else NULL
 */
GptEntry *GptNextKernelEntry(GptData *gpt);

/**
 * Checks if entry name field is equal to name+suffix.
 *
 * Returns true if equal, else false.
 */
bool GptEntryHasName(GptEntry *entry, const char *name,  const char *opt_suffix);

/**
 * Gets GPT entry for specified partition name and suffix.
 *
 * Returns pointer to GPT entry if successful, else NULL
 */
GptEntry *GptFindEntryByName(GptData *gpt, const char *name, const char *opt_suffix);

#endif  /* VBOOT_REFERENCE_CGPTLIB_H_ */
