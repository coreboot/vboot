/* Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include "2common.h"
#include "2sysincludes.h"
#include "cgptlib.h"
#include "cgptlib_internal.h"
#include "crc32.h"
#include "gpt.h"
#include "vboot_api.h"

int GptInit(GptData *gpt)
{
	int retval;

	gpt->modified = 0;
	gpt->current_kernel = CGPT_KERNEL_ENTRY_NOT_FOUND;
	gpt->current_priority = 999;

	retval = GptValidityCheck(gpt);
	if (GPT_SUCCESS != retval) {
		VB2_DEBUG("GptInit() failed validity check\n");
		return retval;
	}

	GptRepair(gpt);
	return GPT_SUCCESS;
}

int GptGetActiveKernelPartitionSuffix(GptData *gpt, char **suffix)
{
	GptEntry *entries = (GptEntry *)gpt->primary_entries;
	GptEntry *e;
	const char suffix_a[] = GPT_ENT_NAME_ANDROID_A_SUFFIX;
	const char suffix_b[] = GPT_ENT_NAME_ANDROID_B_SUFFIX;
	const char *tmp = NULL;
	int max_suffix_len;

	if (gpt->current_kernel == CGPT_KERNEL_ENTRY_NOT_FOUND) {
		VB2_DEBUG("Kernel not selected\n");
		return GPT_ERROR_NO_VALID_KERNEL;
	}

	max_suffix_len = (sizeof(suffix_a) > sizeof(suffix_b)) ?
			 sizeof(suffix_a) : sizeof(suffix_b);

	*suffix = malloc(max_suffix_len);
	if (*suffix == NULL) {
		VB2_DEBUG("Cannot allocate memory for suffix\n");
		return GPT_ERROR_NO_VALID_KERNEL;
	}

	e = &entries[gpt->current_kernel];
	if (IsAndroidBootPartition(e, suffix_a)) {
		tmp = suffix_a;
	} else if (IsAndroidBootPartition(e, suffix_b)) {
		tmp = suffix_b;
	} else {
		free(suffix);
		return GPT_ERROR_NO_VALID_KERNEL;
	}

	strncpy(*suffix, tmp, max_suffix_len);

	return GPT_SUCCESS;
}

int GptNextKernelEntry(GptData *gpt, uint64_t *start_sector, uint64_t *size)
{
	GptHeader *header = (GptHeader *)gpt->primary_header;
	GptEntry *entries = (GptEntry *)gpt->primary_entries;
	GptEntry *e;
	int new_kernel = CGPT_KERNEL_ENTRY_NOT_FOUND;
	int new_prio = 0;
	uint32_t i;

	/*
	 * If we already found a kernel, continue the scan at the current
	 * kernel's priority, in case there is another kernel with the same
	 * priority.
	 */
	if (gpt->current_kernel != CGPT_KERNEL_ENTRY_NOT_FOUND) {
		for (i = gpt->current_kernel + 1;
		     i < header->number_of_entries; i++) {
			e = entries + i;
			if (!IsKernelEntry(e))
				continue;
			VB2_DEBUG("GptNextKernelEntry looking at same prio "
				  "partition %d\n", i+1);
			VB2_DEBUG("GptNextKernelEntry s%d t%d p%d\n",
				  GetEntrySuccessful(e), GetEntryTries(e),
				  GetEntryPriority(e));
			if (!(GetEntrySuccessful(e) || GetEntryTries(e)))
				continue;
			if (GetEntryPriority(e) == gpt->current_priority) {
				gpt->current_kernel = i;
				*start_sector = e->starting_lba;
				*size = e->ending_lba - e->starting_lba + 1;
				VB2_DEBUG("GptNextKernelEntry likes it\n");
				return GPT_SUCCESS;
			}
		}
	}

	/*
	 * We're still here, so scan for the remaining kernel with the highest
	 * priority less than the previous attempt.
	 */
	for (i = 0, e = entries; i < header->number_of_entries; i++, e++) {
		int current_prio = GetEntryPriority(e);
		if (!IsKernelEntry(e))
			continue;
		VB2_DEBUG("GptNextKernelEntry looking at new prio "
			  "partition %d\n", i+1);
		VB2_DEBUG("GptNextKernelEntry s%d t%d p%d\n",
			  GetEntrySuccessful(e), GetEntryTries(e),
			  GetEntryPriority(e));
		if (!(GetEntrySuccessful(e) || GetEntryTries(e)))
			continue;
		if (current_prio >= gpt->current_priority) {
			/* Already returned this kernel in a previous call */
			continue;
		}
		if (current_prio > new_prio) {
			new_kernel = i;
			new_prio = current_prio;
		}
	}

	/*
	 * Save what we found.  Note that if we didn't find a new kernel,
	 * new_prio will still be -1, so future calls to this function will
	 * also fail.
	 */
	gpt->current_kernel = new_kernel;
	gpt->current_priority = new_prio;

	if (CGPT_KERNEL_ENTRY_NOT_FOUND == new_kernel) {
		VB2_DEBUG("GptNextKernelEntry no more kernels\n");
		return GPT_ERROR_NO_VALID_KERNEL;
	}

	VB2_DEBUG("GptNextKernelEntry likes partition %d\n", new_kernel + 1);
	e = entries + new_kernel;
	*start_sector = e->starting_lba;
	*size = e->ending_lba - e->starting_lba + 1;
	return GPT_SUCCESS;
}

/*
 * Func: GptUpdateKernelWithEntry
 * Desc: This function updates the given kernel entry according to the provided
 * update_type.
 */
int GptUpdateKernelWithEntry(GptData *gpt, GptEntry *e, uint32_t update_type)
{
	int modified = 0;

	if (!IsKernelEntry(e))
		return GPT_ERROR_INVALID_UPDATE_TYPE;

	switch (update_type) {
	case GPT_UPDATE_ENTRY_TRY: {
		/* Used up a try */
		int tries;
		if (GetEntrySuccessful(e)) {
			/*
			 * Successfully booted this partition, so tries field
			 * is ignored.
			 */
			return GPT_SUCCESS;
		}
		tries = GetEntryTries(e);
		if (tries > 1) {
			/* Still have tries left */
			modified = 1;
			SetEntryTries(e, tries - 1);
			break;
		}
		/* Out of tries, so drop through and mark partition bad. */
		__attribute__ ((fallthrough));
	}
	case GPT_UPDATE_ENTRY_BAD: {
		/* Giving up on this partition entirely. */
		if (!GetEntrySuccessful(e)) {
			/*
			 * Only clear tries and priority if the successful bit
			 * is not set.
			 */
			modified = 1;
			SetEntryTries(e, 0);
			SetEntryPriority(e, 0);
		}
		break;
	}
	case GPT_UPDATE_ENTRY_ACTIVE: {
		/*
		 * Used for fastboot mode. If kernel partition slot is marked
		 * active, its GPT entry is marked with S1,P2,T0.
		 */
		modified = 1;
		SetEntryTries(e, 0);
		SetEntryPriority(e, 2);
		SetEntrySuccessful(e, 1);
		break;
	}
	case GPT_UPDATE_ENTRY_INVALID: {
		/*
		 * Used for fastboot mode. If kernel partition slot is marked
		 * invalid, its GPT entry is marked with S0,P0,T0
		 */
		modified = 1;
		SetEntryTries(e, 0);
		SetEntryPriority(e, 0);
		SetEntrySuccessful(e, 0);
		break;
	}
	default:
		return GPT_ERROR_INVALID_UPDATE_TYPE;
	}

	if (modified) {
		GptModified(gpt);
	}

	return GPT_SUCCESS;
}

/*
 * Func: GptUpdateKernelEntry
 * Desc: This function updates current_kernel entry with provided
 * update_type. If current_kernel is not set, then it returns error.
 */
int GptUpdateKernelEntry(GptData *gpt, uint32_t update_type)
{
	GptEntry *entries = (GptEntry *)gpt->primary_entries;
	GptEntry *e = entries + gpt->current_kernel;

	if (gpt->current_kernel == CGPT_KERNEL_ENTRY_NOT_FOUND)
		return GPT_ERROR_INVALID_UPDATE_TYPE;

	return GptUpdateKernelWithEntry(gpt, e, update_type);
}

/*
 * Func: GptFindNthEntry
 * Desc: This function returns the nth instance of parition entry matching the
 * partition type guid from the gpt table. Instance value starts from 0. If the
 * entry is not found it returns NULL.
 */
GptEntry *GptFindNthEntry(GptData *gpt, const Guid *guid, unsigned int n)
{
	GptHeader *header = (GptHeader *)gpt->primary_header;
	GptEntry *entries = (GptEntry *)gpt->primary_entries;
	GptEntry *e;
	int i;

	for (i = 0, e = entries; i < header->number_of_entries; i++, e++) {
		if (!memcmp(&e->type, guid, sizeof(*guid))) {
			if (n == 0)
				return e;
			n--;
		}
	}

	return NULL;
}

int GptFindOffsetByName(GptData *gpt, const char *name,
			uint64_t *start_sector, uint64_t *size)
{
	GptHeader *header = (GptHeader *)gpt->primary_header;
	GptEntry *entries = (GptEntry *)gpt->primary_entries;
	GptEntry *e;
	int i;
	uint16_t *name_ucs2;
	int size_ucs2;
	int ret = GPT_ERROR_NO_SUCH_ENTRY;

	name_ucs2 = calloc(NAME_SIZE, sizeof(*name_ucs2));
	if (name_ucs2 == NULL)
		return ret;

	size_ucs2 = UTF8ToUCS2((const uint8_t *)name, name_ucs2, NAME_SIZE - 1);
	if (size_ucs2 < 0)
		goto out;

	for (i = 0, e = entries; i < header->number_of_entries; i++, e++) {
		if (!memcmp(&e->name, name_ucs2, size_ucs2 * sizeof(*name_ucs2))) {
			*start_sector = e->starting_lba;
			*size = e->ending_lba - e->starting_lba + 1;
			ret = GPT_SUCCESS;
			break;
		}
	}

out:
	free(name_ucs2);
	return ret;
}

int GptFindInitBoot(GptData *gpt, uint64_t *start_sector, uint64_t *size)
{
	int ret;
	char *name;
	char *suffix = NULL;

	ret = GptGetActiveKernelPartitionSuffix(gpt, &suffix);
	if (ret != GPT_SUCCESS) {
		VB2_DEBUG("Unable to get kernel partition suffix\n");
		return ret;
	}

	/* Construct name */
	name = JoinStr(GPT_ENT_NAME_ANDROID_INIT_BOOT, suffix);
	free(suffix);
	if (name == NULL) {
		VB2_DEBUG("Unable to construct init_boot partition name\n");
		return GPT_ERROR_INVALID_ENTRIES;
	}

	ret = GptFindOffsetByName(gpt, name, start_sector, size);
	if (ret != GPT_SUCCESS)
		VB2_DEBUG("Unable to find the %s partition\n", name);

	free(name);
	return ret;
}

int GptFindVendorBoot(GptData *gpt, uint64_t *start_sector, uint64_t *size)
{
	int ret;
	char *name;
	char *suffix = NULL;

	ret = GptGetActiveKernelPartitionSuffix(gpt, &suffix);
	if (ret != GPT_SUCCESS) {
		VB2_DEBUG("Unable to get kernel partition suffix\n");
		return ret;
	}

	/* Construct name */
	name = JoinStr(GPT_ENT_NAME_ANDROID_VENDOR_BOOT, suffix);
	free(suffix);
	if (name == NULL) {
		VB2_DEBUG("Unable to construct vendor_boot partition name\n");
		return GPT_ERROR_INVALID_ENTRIES;
	}

	ret = GptFindOffsetByName(gpt, name, start_sector, size);
	if (ret != GPT_SUCCESS)
		VB2_DEBUG("Unable to find the %s partition\n", name);

	free(name);
	return ret;
}
