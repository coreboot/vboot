// SPDX-License-Identifier: GPL-2.0

/*
 * This is from the Android Project,
 * Repository: https://android.googlesource.com/platform/system/tools/mkbootimg
 * File: include/bootimg/bootimg.h
 * Commit: 2fe7d1583e874b45eb678d10e1450a6e70ff4cb4
 *
 * Copyright (C) 2007 The Android Open Source Project
 */

#ifndef ANDROID_IMAGE_HDR
#define ANDROID_IMAGE_HDR

#include <stdint.h>

#define BOOT_MAGIC "ANDROID!"
#define BOOT_MAGIC_SIZE 8
#define BOOT_NAME_SIZE 16
#define BOOT_ARGS_SIZE 512
#define BOOT_EXTRA_ARGS_SIZE 1024

#define VENDOR_BOOT_MAGIC "VNDRBOOT"
#define VENDOR_BOOT_MAGIC_SIZE 8
#define VENDOR_BOOT_ARGS_SIZE 2048
#define VENDOR_BOOT_NAME_SIZE 16

#define VENDOR_RAMDISK_TYPE_NONE 0
#define VENDOR_RAMDISK_TYPE_PLATFORM 1
#define VENDOR_RAMDISK_TYPE_RECOVERY 2
#define VENDOR_RAMDISK_TYPE_DLKM 3
#define VENDOR_RAMDISK_NAME_SIZE 32
#define VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE 16

/* When the boot image header has a version of 4, the structure of the boot
 * image is as follows:
 *
 * +---------------------+
 * | boot header         | 4096 bytes
 * +---------------------+
 * | kernel              | m pages
 * +---------------------+
 * | ramdisk             | n pages
 * +---------------------+
 * | boot signature      | g pages
 * +---------------------+
 *
 * m = (kernel_size + 4096 - 1) / 4096
 * n = (ramdisk_size + 4096 - 1) / 4096
 * g = (signature_size + 4096 - 1) / 4096
 *
 * Note that in version 4 of the boot image header, page size is fixed at 4096
 * bytes.
 *
 * The structure of the vendor boot image version 4, which is required to be
 * present when a version 4 boot image is used, is as follows:
 *
 * +------------------------+
 * | vendor boot header     | o pages
 * +------------------------+
 * | vendor ramdisk section | p pages
 * +------------------------+
 * | dtb                    | q pages
 * +------------------------+
 * | vendor ramdisk table   | r pages
 * +------------------------+
 * | bootconfig             | s pages
 * +------------------------+
 *
 * o = (2128 + page_size - 1) / page_size
 * p = (vendor_ramdisk_size + page_size - 1) / page_size
 * q = (dtb_size + page_size - 1) / page_size
 * r = (vendor_ramdisk_table_size + page_size - 1) / page_size
 * s = (vendor_bootconfig_size + page_size - 1) / page_size
 *
 * Note that in version 4 of the vendor boot image, multiple vendor ramdisks can
 * be included in the vendor boot image. The bootloader can select a subset of
 * ramdisks to load at runtime. To help the bootloader select the ramdisks, each
 * ramdisk is tagged with a type tag and a set of hardware identifiers
 * describing the board, soc or platform that this ramdisk is intended for.
 *
 * The vendor ramdisk section is consist of multiple ramdisk images concatenated
 * one after another, and vendor_ramdisk_size is the size of the section, which
 * is the total size of all the ramdisks included in the vendor boot image.
 *
 * The vendor ramdisk table holds the size, offset, type, name and hardware
 * identifiers of each ramdisk. The type field denotes the type of its content.
 * The vendor ramdisk names are unique. The hardware identifiers are specified
 * in the board_id field in each table entry. The board_id field is consist of a
 * vector of unsigned integer words, and the encoding scheme is defined by the
 * hardware vendor.
 *
 * For the different type of ramdisks, there are:
 *    - VENDOR_RAMDISK_TYPE_NONE indicates the value is unspecified.
 *    - VENDOR_RAMDISK_TYPE_PLATFORM ramdisks contain platform specific bits, so
 *      the bootloader should always load these into memory.
 *    - VENDOR_RAMDISK_TYPE_RECOVERY ramdisks contain recovery resources, so
 *      the bootloader should load these when booting into recovery.
 *    - VENDOR_RAMDISK_TYPE_DLKM ramdisks contain dynamic loadable kernel
 *      modules.
 *
 * Version 4 of the vendor boot image also adds a bootconfig section to the end
 * of the image. This section contains Boot Configuration parameters known at
 * build time. The bootloader is responsible for placing this section directly
 * after the generic ramdisk, followed by the bootconfig trailer, before
 * entering the kernel.
 *
 * 0. all entities in the boot image are 4096-byte aligned in flash, all
 *    entities in the vendor boot image are page_size (determined by the vendor
 *    and specified in the vendor boot image header) aligned in flash
 * 1. kernel, ramdisk, and DTB are required (size != 0)
 * 2. load the kernel and DTB at the specified physical address (kernel_addr,
 *    dtb_addr)
 * 3. load the vendor ramdisks at ramdisk_addr
 * 4. load the generic ramdisk immediately following the vendor ramdisk in
 *    memory
 * 5. load the bootconfig immediately following the generic ramdisk. Add
 *    additional bootconfig parameters followed by the bootconfig trailer.
 * 6. set up registers for kernel entry as required by your architecture
 * 7. if the platform has a second stage bootloader jump to it (must be
 *    contained outside boot and vendor boot partitions), otherwise
 *    jump to kernel_addr
 */
struct boot_img_hdr_v4 {
    // Must be BOOT_MAGIC.
    uint8_t magic[BOOT_MAGIC_SIZE];

    uint32_t kernel_size; /* size in bytes */
    uint32_t ramdisk_size; /* size in bytes */

    // Operating system version and security patch level.
    // For version "A.B.C" and patch level "Y-M-D":
    //   (7 bits for each of A, B, C; 7 bits for (Y-2000), 4 bits for M)
    //   os_version = A[31:25] B[24:18] C[17:11] (Y-2000)[10:4] M[3:0]
    uint32_t os_version;

    uint32_t header_size;

    uint32_t reserved[4];

    // Version of the boot image header.
    uint32_t header_version;

    // Asciiz kernel commandline.
    uint8_t cmdline[BOOT_ARGS_SIZE + BOOT_EXTRA_ARGS_SIZE];
    uint32_t signature_size; /* size in bytes */
} __attribute__((packed));

struct vendor_boot_img_hdr_v4 {
    // Must be VENDOR_BOOT_MAGIC.
    uint8_t magic[VENDOR_BOOT_MAGIC_SIZE];

    // Version of the vendor boot image header.
    uint32_t header_version;

    uint32_t page_size; /* flash page size we assume */

    uint32_t kernel_addr; /* physical load addr */
    uint32_t ramdisk_addr; /* physical load addr */

    uint32_t vendor_ramdisk_size; /* size in bytes */

    uint8_t cmdline[VENDOR_BOOT_ARGS_SIZE]; /* asciiz kernel commandline */

    uint32_t tags_addr; /* physical addr for kernel tags (if required) */
    uint8_t name[VENDOR_BOOT_NAME_SIZE]; /* asciiz product name */

    uint32_t header_size;

    uint32_t dtb_size; /* size in bytes for DTB image */
    uint64_t dtb_addr; /* physical load address for DTB image */

    uint32_t vendor_ramdisk_table_size; /* size in bytes for the vendor ramdisk table */
    uint32_t vendor_ramdisk_table_entry_num; /* number of entries in the vendor ramdisk table */
    uint32_t vendor_ramdisk_table_entry_size; /* size in bytes for a vendor ramdisk table entry */
    uint32_t bootconfig_size; /* size in bytes for the bootconfig section */
} __attribute__((packed));

struct vendor_ramdisk_table_entry_v4 {
    uint32_t ramdisk_size; /* size in bytes for the ramdisk image */
    uint32_t ramdisk_offset; /* offset to the ramdisk image in vendor ramdisk section */
    uint32_t ramdisk_type; /* type of the ramdisk */
    uint8_t ramdisk_name[VENDOR_RAMDISK_NAME_SIZE]; /* asciiz ramdisk name */

    // Hardware identifiers describing the board, soc or platform which this
    // ramdisk is intended to be loaded on.
    uint32_t board_id[VENDOR_RAMDISK_TABLE_ENTRY_BOARD_ID_SIZE];
} __attribute__((packed));

#endif /* ANDROID_IMAGE_HDR */
