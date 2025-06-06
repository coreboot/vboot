/* Copyright 2012 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#include <stdio.h>
#include <string.h>

#include "cgpt.h"
#include "cgptlib_internal.h"
#include "cgpt_params.h"
#include "vboot_host.h"

static void PrintCgptAddParams(const CgptAddParams *params)
{
	char tmp[64];

	fprintf(stderr, "-i %d ", params->partition);
	if (params->label)
		fprintf(stderr, "-l %s ", params->label);
	if (params->set_begin)
		fprintf(stderr, "-b %llu ", (unsigned long long)params->begin);
	if (params->set_size)
		fprintf(stderr, "-s %llu ", (unsigned long long)params->size);
	if (params->set_type) {
		GptGuidToStr(&params->type_guid, tmp, sizeof(tmp), GPT_GUID_UPPERCASE);
		fprintf(stderr, "-t %s ", tmp);
	}
	if (params->set_unique) {
		GptGuidToStr(&params->unique_guid, tmp, sizeof(tmp), GPT_GUID_UPPERCASE);
		fprintf(stderr, "-u %s ", tmp);
	}
	if (params->set_error_counter)
		fprintf(stderr, "-E %d ", params->error_counter);
	if (params->set_successful)
		fprintf(stderr, "-S %d ", params->successful);
	if (params->set_tries)
		fprintf(stderr, "-T %d ", params->tries);
	if (params->set_priority)
		fprintf(stderr, "-P %d ", params->priority);
	if (params->set_required)
		fprintf(stderr, "-R %d ", params->required);
	if (params->set_legacy_boot)
		fprintf(stderr, "-B %d ", params->legacy_boot);
	if (params->set_raw)
		fprintf(stderr, "-A %#x ", params->raw_value);

	fprintf(stderr, "\n");
}

// This is the implementation-specific helper function.
static int GptSetEntryAttributes(struct drive *drive, uint32_t index, CgptAddParams *params)
{
	GptEntry *entry;

	entry = GetEntry(&drive->gpt, PRIMARY, index);
	if (params->set_begin)
		entry->starting_lba = params->begin;
	if (params->set_size)
		entry->ending_lba = entry->starting_lba + params->size - 1;
	if (params->set_unique) {
		memcpy(&entry->unique, &params->unique_guid, sizeof(Guid));
	} else if (GuidIsZero(&entry->type)) {
		if (CGPT_OK != GenerateGuid(&entry->unique)) {
			Error("Unable to generate new GUID.\n");
			return -1;
		}
	}
	if (params->set_type)
		memcpy(&entry->type, &params->type_guid, sizeof(Guid));
	if (params->label) {
		if (CGPT_OK != UTF8ToUTF16((const uint8_t *)params->label, entry->name,
					   sizeof(entry->name) / sizeof(entry->name[0]))) {
			Error("The label cannot be converted to UTF16.\n");
			return -1;
		}
	}
	return 0;
}

// This is an internal helper function which assumes no NULL args are passed.
// It sets the given attribute values for a single entry at the given index.
static int SetEntryAttributes(struct drive *drive, uint32_t index, CgptAddParams *params)
{
	if (params->set_raw) {
		SetRaw(drive, PRIMARY, index, params->raw_value);
	} else {
		if (params->set_error_counter)
			SetErrorCounter(drive, PRIMARY, index, params->error_counter);
		if (params->set_successful)
			SetSuccessful(drive, PRIMARY, index, params->successful);
		if (params->set_tries)
			SetTries(drive, PRIMARY, index, params->tries);
		if (params->set_priority)
			SetPriority(drive, PRIMARY, index, params->priority);
		if (params->set_legacy_boot)
			SetLegacyBoot(drive, PRIMARY, index, params->legacy_boot);
		if (params->set_required)
			SetRequired(drive, PRIMARY, index, params->required);
	}

	// New partitions must specify type, begin, and size.
	if (IsUnused(drive, PRIMARY, index)) {
		if (!params->set_begin || !params->set_size || !params->set_type) {
			Error("-t, -b, and -s options are required for new partitions\n");
			return -1;
		}
		if (GuidIsZero(&params->type_guid)) {
			Error("New partitions must have a type other than \"unused\"\n");
			return -1;
		}
	}

	return 0;
}

static int CgptCheckAddValidity(struct drive *drive)
{
	int gpt_retval;
	if (GPT_SUCCESS != (gpt_retval = GptValidityCheck(&drive->gpt))) {
		Error("GptValidityCheck() returned %d: %s\n", gpt_retval, GptError(gpt_retval));
		return -1;
	}

	if (CGPT_OK != CheckValid(drive)) {
		Error("please run 'cgpt repair' before adding anything.\n");
		return -1;
	}

	return 0;
}

static int CgptGetUnusedPartition(struct drive *drive, uint32_t *index, CgptAddParams *params)
{
	uint32_t i;
	uint32_t max_part = GetNumberOfEntries(drive);
	if (params->partition) {
		if (params->partition > max_part) {
			Error("invalid partition number: %d\n", params->partition);
			return -1;
		}
		*index = params->partition - 1;
		return 0;
	} else {
		// Find next empty partition.
		for (i = 0; i < max_part; i++) {
			if (IsUnused(drive, PRIMARY, i)) {
				params->partition = i + 1;
				*index = i;
				return 0;
			}
		}
		Error("no unused partitions available\n");
		return -1;
	}
}

int CgptSetAttributes(CgptAddParams *params)
{
	struct drive drive;

	if (params == NULL)
		return CGPT_FAILED;

	if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDWR, params->drive_size))
		return CGPT_FAILED;

	if (CgptCheckAddValidity(&drive)) {
		goto bad;
	}

	if (params->partition == 0 || params->partition >= GetNumberOfEntries(&drive)) {
		Error("invalid partition number: %d\n", params->partition);
		goto bad;
	}

	SetEntryAttributes(&drive, params->partition - 1, params);

	UpdateAllEntries(&drive);

	// Write it all out.
	return DriveClose(&drive, 1);

bad:
	DriveClose(&drive, 0);
	return CGPT_FAILED;
}

// This method gets the partition details such as the attributes, the
// guids of the partitions, etc. Input is the partition number or the
// unique id of the partition. Output is populated in the respective
// fields of params.
int CgptGetPartitionDetails(CgptAddParams *params)
{
	struct drive drive;
	int result = CGPT_FAILED;
	int index;

	if (params == NULL)
		return CGPT_FAILED;

	if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDONLY, params->drive_size))
		return CGPT_FAILED;

	if (CgptCheckAddValidity(&drive)) {
		goto bad;
	}

	int max_part = GetNumberOfEntries(&drive);
	if (params->partition > 0) {
		if (params->partition >= max_part) {
			Error("invalid partition number: %d\n", params->partition);
			goto bad;
		}
	} else {
		if (!params->set_unique) {
			Error("either partition or unique_id must be specified\n");
			goto bad;
		}
		for (index = 0; index < max_part; index++) {
			GptEntry *entry = GetEntry(&drive.gpt, PRIMARY, index);
			if (GuidEqual(&entry->unique, &params->unique_guid)) {
				params->partition = index + 1;
				break;
			}
		}
		if (index >= max_part) {
			Error("no partitions with the given unique id available\n");
			goto bad;
		}
	}
	index = params->partition - 1;

	// GPT-specific code
	GptEntry *entry = GetEntry(&drive.gpt, PRIMARY, index);
	params->begin = entry->starting_lba;
	params->size = entry->ending_lba - entry->starting_lba + 1;
	memcpy(&params->type_guid, &entry->type, sizeof(Guid));
	memcpy(&params->unique_guid, &entry->unique, sizeof(Guid));
	params->raw_value = entry->attrs.fields.gpt_att;

	params->error_counter = GetErrorCounter(&drive, PRIMARY, index);
	params->successful = GetSuccessful(&drive, PRIMARY, index);
	params->tries = GetTries(&drive, PRIMARY, index);
	params->priority = GetPriority(&drive, PRIMARY, index);
	result = CGPT_OK;

bad:
	DriveClose(&drive, 0);
	return result;
}

static int GptAdd(struct drive *drive, CgptAddParams *params, uint32_t index)
{
	GptEntry *entry, backup;
	int rv;

	entry = GetEntry(&drive->gpt, PRIMARY, index);
	memcpy(&backup, entry, sizeof(backup));

	if (SetEntryAttributes(drive, index, params) ||
	    GptSetEntryAttributes(drive, index, params)) {
		memcpy(entry, &backup, sizeof(*entry));
		return -1;
	}

	UpdateAllEntries(drive);

	rv = CheckEntries((GptEntry *)drive->gpt.primary_entries,
			  (GptHeader *)drive->gpt.primary_header);

	if (0 != rv) {
		// If the modified entry is illegal, recover it and return error.
		memcpy(entry, &backup, sizeof(*entry));
		Error("%s\n", GptErrorText(rv));
		Error("");
		PrintCgptAddParams(params);
		return -1;
	}

	return 0;
}

int CgptAdd(CgptAddParams *params)
{
	struct drive drive;
	uint32_t index;

	if (params == NULL)
		return CGPT_FAILED;

	if (CGPT_OK != DriveOpen(params->drive_name, &drive, O_RDWR, params->drive_size))
		return CGPT_FAILED;

	if (CgptCheckAddValidity(&drive)) {
		goto bad;
	}

	if (CgptGetUnusedPartition(&drive, &index, params)) {
		goto bad;
	}

	if (GptAdd(&drive, params, index))
		goto bad;

	// Write it all out.
	return DriveClose(&drive, 1);

bad:
	DriveClose(&drive, 0);
	return CGPT_FAILED;
}
