/* Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * APIs provided by firmware to vboot_reference.
 *
 * General notes:
 *
 * All verified boot functions now start with "Vb" for namespace clarity.  This
 * fixes the problem where uboot and vboot both defined assert().
 *
 * Verified boot APIs to be implemented by the calling firmware and exported to
 * vboot_reference start with "VbEx".
 *
 * TODO: split this file into a vboot_entry_points.h file which contains the
 * entry points for the firmware to call vboot_reference, and a
 * vboot_firmware_exports.h which contains the APIs to be implemented by the
 * calling firmware and exported to vboot_reference.
 */

#ifndef VBOOT_REFERENCE_VBOOT_API_H_
#define VBOOT_REFERENCE_VBOOT_API_H_

#include <stdint.h>
#include <stdlib.h>

#include "../2lib/include/2constants.h"
#include "../2lib/include/2return_codes.h"
#include "gpt.h"

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

struct vb2_context;
struct vb2_disk_info;
typedef struct VbSharedDataHeader VbSharedDataHeader;

/*****************************************************************************/
/* Disk access (previously in boot_device.h) */

/**
 * Store information into [info] for all disks (storage devices) attached to
 * the system which match all of the disk_flags.
 *
 * On output, count indicates how many disks are present, and [infos_ptr]
 * points to a [count]-sized array of vb2_disk_info structs with the information
 * on those disks; this pointer must be freed by calling VbExDiskFreeInfo().
 * If count=0, infos_ptr may point to NULL.  If [infos_ptr] points to NULL
 * because count=0 or error, it is not necessary to call VbExDiskFreeInfo().
 *
 * A multi-function device (such as a 4-in-1 card reader) should provide
 * multiple disk handles.
 *
 * The firmware must not alter or free the list pointed to by [infos_ptr] until
 * VbExDiskFreeInfo() is called.
 */
vb2_error_t VbExDiskGetInfo(struct vb2_disk_info **infos_ptr, uint32_t *count,
			    uint32_t disk_flags);

/**
 * Free a disk information list [infos] previously returned by
 * VbExDiskGetInfo().  If [preserve_handle] != NULL, the firmware must ensure
 * that handle remains valid after this call; all other handles from the info
 * list need not remain valid after this call.
 */
vb2_error_t VbExDiskFreeInfo(struct vb2_disk_info *infos,
			     vb2ex_disk_handle_t preserve_handle);

/**
 * Read lba_count LBA sectors, starting at sector lba_start, from the disk,
 * into the buffer.
 *
 * This is used for random access to the GPT. It is not for the partition
 * contents. The upper limit is lba_count.
 *
 * If the disk handle is invalid (for example, the handle refers to a disk
 * which as been removed), the function must return error but must not
 * crash.
 */
vb2_error_t VbExDiskRead(vb2ex_disk_handle_t handle, uint64_t lba_start,
			 uint64_t lba_count, void *buffer);

/**
 * Write lba_count LBA sectors, starting at sector lba_start, to the disk, from
 * the buffer.
 *
 * This is used for random access to the GPT. It does not (necessarily) access
 * the streaming portion of the device.
 *
 * If the disk handle is invalid (for example, the handle refers to a disk
 * which as been removed), the function must return error but must not
 * crash.
 */
vb2_error_t VbExDiskWrite(vb2ex_disk_handle_t handle, uint64_t lba_start,
			  uint64_t lba_count, const void *buffer);

/* Streaming read interface */
typedef void *VbExStream_t;

/**
 * Open a stream on a disk
 *
 * @param handle	Disk to open the stream against
 * @param lba_start	Starting sector offset within the disk to stream from
 * @param lba_count	Maximum extent of the stream in sectors
 * @param stream	out-paramter for the generated stream
 *
 * @return Error code, or VB2_SUCCESS.
 *
 * This is used for access to the contents of the actual partitions on the
 * device. It is not used to access the GPT. The size of the content addressed
 * is within streaming_lba_count.
 */
vb2_error_t VbExStreamOpen(vb2ex_disk_handle_t handle, uint64_t lba_start,
			   uint64_t lba_count, VbExStream_t *stream_ptr);

/**
 * Read from a stream on a disk
 *
 * @param stream	Stream to read from
 * @param bytes		Number of bytes to read
 * @param buffer	Destination to read into
 *
 * @return Error code, or VB2_SUCCESS. Failure to read as much data as
 * requested is an error.
 *
 * This is used for access to the contents of the actual partitions on the
 * device. It is not used to access the GPT.
 */
vb2_error_t VbExStreamRead(VbExStream_t stream, uint32_t bytes, void *buffer);

/**
 * Close a stream
 *
 * @param stream	Stream to close
 */
void VbExStreamClose(VbExStream_t stream);

#ifdef __cplusplus
}
#endif  /* __cplusplus */

#endif  /* VBOOT_REFERENCE_VBOOT_API_H_ */
