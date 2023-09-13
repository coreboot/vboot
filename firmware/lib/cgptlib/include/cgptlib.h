/* Copyright 2013 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef VBOOT_REFERENCE_CGPTLIB_H_
#define VBOOT_REFERENCE_CGPTLIB_H_

#include "2sysincludes.h"
#include "gpt_misc.h"

enum GptPartition {
	GPT_ANDROID_BOOT,
	GPT_ANDROID_INIT_BOOT,
	GPT_ANDROID_VENDOR_BOOT,
	GPT_ANDROID_PVMFW,
	GPT_ANDROID_MISC,
};

extern const char *GptPartitionNames[];

/**
 * Provides the location of the next kernel partition, in order of decreasing
 * priority.
 *
 * On return the start_sector parameter contains the LBA sector for the start
 * of the kernel partition, and the size parameter contains the size of the
 * kernel partition in LBA sectors.  gpt.current_kernel contains the partition
 * index of the current chromeos kernel partition.
 *
 * Returns GPT_SUCCESS if successful, else
 *   GPT_ERROR_NO_VALID_KERNEL, no avaliable kernel, enters recovery mode */
int GptNextKernelEntry(GptData *gpt, uint64_t *start_sector, uint64_t *size);

/**
 * Checks is entry name field is equal to name+suffix.
 *
 * Returns true if equal, else false.
 */
bool GptEntryHasName(GptEntry *entry, const char *name,  const char *opt_suffix);

/**
 * Get GPT entry for specified partition name and suffix.
 *
 * Returns pointer to GPT entry if successful, else NULL
 */
GptEntry *GptFindEntryByName(GptData *gpt, const char *name, const char *suffix);

#endif  /* VBOOT_REFERENCE_CGPTLIB_H_ */
