/* Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 *
 * Tests for TPM secure data space functions
 */

#include "2api.h"
#include "2secdata.h"
#include "secdata_tpm.h"
#include "test_common.h"
#include "tlcl.h"
#include "tss_constants.h"
#include "vboot_test.h"

/*
 * Buffer to hold accumulated list of calls to mocked Tlcl functions.
 * Each function appends itself to the buffer and updates mock_cnext.
 *
 * Size of mock_calls[] should be big enough to handle all expected
 * call sequences; 16KB should be plenty since none of the sequences
 * below is more than a few hundred bytes.  We could be more clever
 * and use snprintf() with length checking below, at the expense of
 * making all the mock implementations bigger.  If this were code used
 * outside of unit tests we'd want to do that, but here if we did
 * overrun the buffer the worst that's likely to happen is we'll crash
 * the test, and crash = failure anyway.
 */
static char mock_calls[16384];
static char *mock_cnext = mock_calls;

/*
 * Variables to support mocked error values from Tlcl functions.  Each
 * call, mock_count is incremented.  If mock_count==fail_at_count, return
 * fail_with_error instead of the normal return value.
 */
static int mock_count = 0;
static int fail_at_count = 0;
static uint32_t fail_with_error = TPM_SUCCESS;
static int mock_bad_crc = 0;

/* Params / backing store for mocked Tlcl functions. */
static TPM_PERMANENT_FLAGS mock_pflags;
static uint8_t mock_rsf[VB2_SECDATA_FIRMWARE_SIZE];
static uint8_t mock_rsk[VB2_SECDATA_KERNEL_SIZE];
static uint8_t mock_fwmp[VB2_SECDATA_FWMP_MAX_SIZE];
static uint32_t mock_fwmp_real_size;
static uint32_t mock_permissions;

static uint8_t workbuf[VB2_FIRMWARE_WORKBUF_RECOMMENDED_SIZE]
	__attribute__ ((aligned (VB2_WORKBUF_ALIGN)));
static struct vb2_context *ctx;

/* Reset the variables for the Tlcl mock functions. */
static void reset_common_data(int fail_on_call, uint32_t fail_with_err)
{
	*mock_calls = 0;
	mock_cnext = mock_calls;
	mock_count = 0;
	fail_at_count = fail_on_call;
	fail_with_error = fail_with_err;
	mock_bad_crc = 0;

	memset(&mock_pflags, 0, sizeof(mock_pflags));

	/* Use value other than 0 for memcmp() checks */
	memset(&mock_rsf, 0xa6, sizeof(mock_rsf));
	memset(&mock_rsk, 0xa7, sizeof(mock_rsk));
	memset(&mock_fwmp, 0xa8, sizeof(mock_fwmp));

	mock_fwmp_real_size = VB2_SECDATA_FWMP_MIN_SIZE;

	/* Note: only used when TPM2_MODE is disabled. */
#ifndef TPM2_MODE
	mock_permissions = TPM_NV_PER_PPWRITE;
#else
	mock_permissions = 0;
#endif

	secdata_kernel_locked = 0;

	TEST_SUCC(vb2api_init(workbuf, sizeof(workbuf), &ctx),
		  "vb2api_init failed");

	ctx->flags |= VB2_CONTEXT_SECDATA_FIRMWARE_CHANGED;
	ctx->flags |= VB2_CONTEXT_SECDATA_KERNEL_CHANGED;
	ctx->flags |= VB2_CONTEXT_RECOVERY_MODE;
}

/* Mock functions */

vb2_error_t vb2api_secdata_firmware_check(struct vb2_context *c)
{
	if (mock_bad_crc)
		return VB2_ERROR_SECDATA_FIRMWARE_CRC;

	return VB2_SUCCESS;
}

vb2_error_t vb2api_secdata_kernel_check(struct vb2_context *c)
{
	if (mock_bad_crc)
		return VB2_ERROR_SECDATA_FIRMWARE_CRC;

	return VB2_SUCCESS;
}

vb2_error_t vb2api_secdata_fwmp_check(struct vb2_context *c, uint8_t *size)
{
	if (*size < mock_fwmp_real_size) {
		*size = mock_fwmp_real_size;
		return VB2_ERROR_SECDATA_FWMP_INCOMPLETE;
	}

	if (mock_bad_crc)
		return VB2_ERROR_SECDATA_FIRMWARE_CRC;

	return VB2_SUCCESS;
}

/****************************************************************************/
/* Mocks for tlcl functions which log the calls made to mock_calls[]. */

uint32_t TlclLibInit(void)
{
	mock_cnext += sprintf(mock_cnext, "TlclLibInit()\n");
	return (++mock_count == fail_at_count) ? fail_with_error : TPM_SUCCESS;
}

uint32_t TlclStartup(void)
{
	mock_cnext += sprintf(mock_cnext, "TlclStartup()\n");
	return (++mock_count == fail_at_count) ? fail_with_error : TPM_SUCCESS;
}

uint32_t TlclResume(void)
{
	mock_cnext += sprintf(mock_cnext, "TlclResume()\n");
	return (++mock_count == fail_at_count) ? fail_with_error : TPM_SUCCESS;
}

uint32_t TlclForceClear(void)
{
	mock_cnext += sprintf(mock_cnext, "TlclForceClear()\n");
	return (++mock_count == fail_at_count) ? fail_with_error : TPM_SUCCESS;
}

uint32_t TlclSetEnable(void)
{
	mock_cnext += sprintf(mock_cnext, "TlclSetEnable()\n");
	return (++mock_count == fail_at_count) ? fail_with_error : TPM_SUCCESS;
}

uint32_t TlclSetDeactivated(uint8_t flag)
{
	mock_cnext += sprintf(mock_cnext, "TlclSetDeactivated(%d)\n", flag);
	return (++mock_count == fail_at_count) ? fail_with_error : TPM_SUCCESS;
}

uint32_t TlclRead(uint32_t index, void* data, uint32_t length)
{
	mock_cnext += sprintf(mock_cnext, "TlclRead(%#x, %d)\n",
			      index, length);

	if (FIRMWARE_NV_INDEX == index) {
		TEST_EQ(length, sizeof(mock_rsf), "TlclRead rsf size");
		memcpy(data, &mock_rsf, length);
	} else if (KERNEL_NV_INDEX == index) {
		TEST_EQ(length, sizeof(mock_rsk), "TlclRead rsk size");
		memcpy(data, &mock_rsk, length);
	} else if (FWMP_NV_INDEX == index) {
		memset(data, 0, length);
		if (length > sizeof(mock_fwmp))
			length = sizeof(mock_fwmp);
		memcpy(data, &mock_fwmp, length);
	} else {
		memset(data, 0, length);
	}

	return (++mock_count == fail_at_count) ? fail_with_error : TPM_SUCCESS;
}

uint32_t TlclWrite(uint32_t index, const void *data, uint32_t length)
{
	mock_cnext += sprintf(mock_cnext, "TlclWrite(%#x, %d)\n",
			      index, length);

	if (FIRMWARE_NV_INDEX == index) {
		TEST_EQ(length, sizeof(mock_rsf), "TlclWrite rsf size");
		memcpy(&mock_rsf, data, length);
	} else if (KERNEL_NV_INDEX == index) {
		TEST_EQ(length, sizeof(mock_rsk), "TlclWrite rsk size");
		memcpy(&mock_rsk, data, length);
	}

	return (++mock_count == fail_at_count) ? fail_with_error : TPM_SUCCESS;
}

uint32_t TlclDefineSpace(uint32_t index, uint32_t perm, uint32_t size)
{
	mock_cnext += sprintf(mock_cnext, "TlclDefineSpace(%#x, %#x, %d)\n",
			      index, perm, size);
	return (++mock_count == fail_at_count) ? fail_with_error : TPM_SUCCESS;
}

uint32_t TlclSelfTestFull(void)
{
	mock_cnext += sprintf(mock_cnext, "TlclSelfTestFull()\n");
	return (++mock_count == fail_at_count) ? fail_with_error : TPM_SUCCESS;
}

uint32_t TlclContinueSelfTest(void)
{
	mock_cnext += sprintf(mock_cnext, "TlclContinueSelfTest()\n");
	return (++mock_count == fail_at_count) ? fail_with_error : TPM_SUCCESS;
}

uint32_t TlclGetPermanentFlags(TPM_PERMANENT_FLAGS *pflags)
{
	mock_cnext += sprintf(mock_cnext, "TlclGetPermanentFlags()\n");
	memcpy(pflags, &mock_pflags, sizeof(mock_pflags));
	return (++mock_count == fail_at_count) ? fail_with_error : TPM_SUCCESS;
}

/* TlclGetFlags() doesn't need mocking; it calls TlclGetPermanentFlags() */

uint32_t TlclAssertPhysicalPresence(void)
{
	mock_cnext += sprintf(mock_cnext, "TlclAssertPhysicalPresence()\n");
	return (++mock_count == fail_at_count) ? fail_with_error : TPM_SUCCESS;
}

uint32_t TlclPhysicalPresenceCMDEnable(void)
{
	mock_cnext += sprintf(mock_cnext, "TlclPhysicalPresenceCMDEnable()\n");
	return (++mock_count == fail_at_count) ? fail_with_error : TPM_SUCCESS;
}

uint32_t TlclSetGlobalLock(void)
{
	mock_cnext += sprintf(mock_cnext, "TlclSetGlobalLock()\n");
	return (++mock_count == fail_at_count) ? fail_with_error : TPM_SUCCESS;
}

uint32_t TlclLockPhysicalPresence(void)
{
	mock_cnext += sprintf(mock_cnext, "TlclLockPhysicalPresence()\n");
	return (++mock_count == fail_at_count) ? fail_with_error : TPM_SUCCESS;
}

#ifndef TPM2_MODE
uint32_t TlclGetPermissions(uint32_t index, uint32_t* permissions)
{
	mock_cnext += sprintf(mock_cnext, "TlclGetPermissions(%#x)\n", index);
	*permissions = mock_permissions;
	return (++mock_count == fail_at_count) ? fail_with_error : TPM_SUCCESS;
}

uint32_t TlclFinalizePhysicalPresence(void)
{
	mock_cnext += sprintf(mock_cnext, "TlclFinalizePhysicalPresence()\n");
	mock_pflags.physicalPresenceLifetimeLock = 1;
	return (++mock_count == fail_at_count) ? fail_with_error : TPM_SUCCESS;
}

uint32_t TlclSetNvLocked(void)
{
	mock_cnext += sprintf(mock_cnext, "TlclSetNvLocked()\n");
	mock_pflags.nvLocked = 1;
	return (++mock_count == fail_at_count) ? fail_with_error : TPM_SUCCESS;
}
#endif

/****************************************************************************/
/* Tests for misc helper functions */

static void misc_tests(void)
{
	uint8_t buf[8];

	reset_common_data(0, 0);
	TEST_EQ(tlcl_clear_and_reenable(), 0, "tlcl_clear_and_enable()");
	TEST_STR_EQ(mock_calls,
		    "TlclForceClear()\n"
		    "TlclSetEnable()\n"
		    "TlclSetDeactivated(0)\n",
		    "  tlcl calls");

	reset_common_data(0, 0);
	TEST_EQ(tlcl_safe_write(0x123, buf, 8), 0, "tlcl_safe_write()");
	TEST_STR_EQ(mock_calls,
		    "TlclWrite(0x123, 8)\n",
		    "  tlcl calls");

	reset_common_data(1, TPM_E_BADINDEX);
	TEST_EQ(tlcl_safe_write(0x123, buf, 8), TPM_E_BADINDEX,
		"tlcl_safe_write() bad");
	TEST_STR_EQ(mock_calls,
		    "TlclWrite(0x123, 8)\n",
		    "  tlcl calls");

	reset_common_data(1, TPM_E_MAXNVWRITES);
	TEST_EQ(tlcl_safe_write(0x123, buf, 8), 0,
		"tlcl_safe_write() retry max writes");
	TEST_STR_EQ(mock_calls,
		    "TlclWrite(0x123, 8)\n"
		    "TlclForceClear()\n"
		    "TlclSetEnable()\n"
		    "TlclSetDeactivated(0)\n"
		    "TlclWrite(0x123, 8)\n",
		    "  tlcl calls");
}

/****************************************************************************/
/* Tests for firmware space functions */

static void secdata_firmware_tests(void)
{
	/* Write with no new changes */
	reset_common_data(0, 0);
	ctx->flags &= ~VB2_CONTEXT_SECDATA_FIRMWARE_CHANGED;
	TEST_SUCC(secdata_firmware_write(ctx),
		  "secdata_firmware_write(), no changes, success");
	TEST_STR_EQ(mock_calls,
		    "",
		    "  tlcl calls");

	/* Write failure */
	reset_common_data(1, TPM_E_IOERROR);
	TEST_EQ(secdata_firmware_write(ctx), TPM_E_IOERROR,
		"secdata_firmware_write(), failure");
	TEST_STR_EQ(mock_calls,
		    "TlclWrite(0x1007, 10)\n",
		    "  tlcl calls");
	TEST_NEQ(ctx->flags & VB2_CONTEXT_SECDATA_FIRMWARE_CHANGED, 0,
		 "  should leave SECDATA_FIRMWARE_CHANGED context flag");

	/* Write in normal mode */
	reset_common_data(0, 0);
	ctx->flags &= ~VB2_CONTEXT_RECOVERY_MODE;
	TEST_EQ(secdata_firmware_write(ctx), TPM_E_AREA_LOCKED,
		"secdata_firmware_write(), normal mode, failure");
	TEST_STR_EQ(mock_calls,
		    "",
		    "  tlcl calls");
	TEST_NEQ(ctx->flags & VB2_CONTEXT_SECDATA_FIRMWARE_CHANGED, 0,
		 "  should leave SECDATA_FIRMWARE_CHANGED context flag");

	/* Write success and readback */
	reset_common_data(0, 0);
	memset(ctx->secdata_firmware, 0xaa, sizeof(ctx->secdata_firmware));
	TEST_SUCC(secdata_firmware_write(ctx),
		  "secdata_firmware_write(), success");
	TEST_STR_EQ(mock_calls,
		    "TlclWrite(0x1007, 10)\n",
		    "  tlcl calls");
	memset(ctx->secdata_firmware, 0xaa, sizeof(ctx->secdata_firmware));
	TEST_EQ(memcmp(ctx->secdata_firmware, &mock_rsf,
		       sizeof(ctx->secdata_firmware)), 0,
		"  unchanged on readback");
	TEST_EQ(ctx->flags & VB2_CONTEXT_SECDATA_FIRMWARE_CHANGED, 0,
		"  should reset SECDATA_FIRMWARE_CHANGED context flag");
}

/****************************************************************************/
/* Tests for kernel space functions */

static void secdata_kernel_tests(void)
{
	/* Not present is an error */
	reset_common_data(1, TPM_E_BADINDEX);
	TEST_EQ(secdata_kernel_read(ctx), TPM_E_BADINDEX,
		"secdata_kernel_read(), not present");
	TEST_STR_EQ(mock_calls,
#ifndef TPM2_MODE
		    "TlclGetPermissions(0x1008)\n",
#else
		    "TlclRead(0x1008, 13)\n",
#endif
		    "  tlcl calls");

#ifndef TPM2_MODE
	/* Bad permissions */
	reset_common_data(0, 0);
	mock_permissions = 0;
	TEST_EQ(secdata_kernel_read(ctx), TPM_E_CORRUPTED_STATE,
		"secdata_kernel_read(), bad permissions");
	TEST_STR_EQ(mock_calls,
		    "TlclGetPermissions(0x1008)\n",
		    "  tlcl calls");
#endif

	/* Good permissions, read failure */
#ifndef TPM2_MODE
	int read_failure_on_call = 2;
#else
	int read_failure_on_call = 1;
#endif
	reset_common_data(read_failure_on_call, TPM_E_IOERROR);
	TEST_EQ(secdata_kernel_read(ctx), TPM_E_IOERROR,
		"secdata_kernel_read(), good permissions, failure");
	TEST_STR_EQ(mock_calls,
#ifndef TPM2_MODE
		    "TlclGetPermissions(0x1008)\n"
#endif
		    "TlclRead(0x1008, 13)\n",
		    "  tlcl calls");

	/* Good permissions, read success, bad CRC */
	reset_common_data(0, 0);
	mock_bad_crc = 1;
	TEST_EQ(secdata_kernel_read(ctx), TPM_E_CORRUPTED_STATE,
		"secdata_kernel_read(), read success, bad CRC");
	TEST_STR_EQ(mock_calls,
#ifndef TPM2_MODE
		    "TlclGetPermissions(0x1008)\n"
#endif
		    "TlclRead(0x1008, 13)\n",
		    "  tlcl calls");

	/* Good permissions, read success */
	reset_common_data(0, 0);
	TEST_SUCC(secdata_kernel_read(ctx),
		  "secdata_kernel_read(), good permissions, success");
	TEST_STR_EQ(mock_calls,
#ifndef TPM2_MODE
		    "TlclGetPermissions(0x1008)\n"
#endif
		    "TlclRead(0x1008, 13)\n",
		    "  tlcl calls");
	TEST_EQ(memcmp(ctx->secdata_kernel, &mock_rsk,
		       sizeof(ctx->secdata_kernel)), 0, "  data");

	/* Write with no new changes */
	reset_common_data(0, 0);
	ctx->flags &= ~VB2_CONTEXT_SECDATA_KERNEL_CHANGED;
	TEST_SUCC(secdata_kernel_write(ctx),
		  "secdata_kernel_write(), no changes, success");
	TEST_STR_EQ(mock_calls,
		    "",
		    "  tlcl calls");

	/* Write failure */
	reset_common_data(1, TPM_E_IOERROR);
	TEST_EQ(secdata_kernel_write(ctx), TPM_E_IOERROR,
		"secdata_kernel_write(), failure");
	TEST_STR_EQ(mock_calls,
		    "TlclWrite(0x1008, 13)\n",
		    "  tlcl calls");
	TEST_NEQ(ctx->flags & VB2_CONTEXT_SECDATA_KERNEL_CHANGED, 0,
		 "  should leave SECDATA_KERNEL_CHANGED context flag");

	/* Write success and readback */
	reset_common_data(0, 0);
	memset(ctx->secdata_kernel, 0xaa, sizeof(ctx->secdata_kernel));
	TEST_SUCC(secdata_kernel_write(ctx),
		  "secdata_kernel_write(), failure");
	TEST_STR_EQ(mock_calls,
		    "TlclWrite(0x1008, 13)\n",
		    "  tlcl calls");
	memset(ctx->secdata_kernel, 0xaa, sizeof(ctx->secdata_kernel));
	TEST_EQ(memcmp(ctx->secdata_kernel, &mock_rsk,
		       sizeof(ctx->secdata_kernel)), 0,
		"  unchanged on readback");
	TEST_EQ(ctx->flags & VB2_CONTEXT_SECDATA_KERNEL_CHANGED, 0,
		"  should reset SECDATA_KERNEL_CHANGED context flag");

	/* Lock in normal mode with failure */
	reset_common_data(1, TPM_E_AREA_LOCKED);
	TEST_EQ(secdata_kernel_lock(ctx), TPM_E_AREA_LOCKED,
		"secdata_kernel_lock(), lock failure");
	TEST_STR_EQ(mock_calls,
		    "TlclLockPhysicalPresence()\n",
		    "  tlcl calls");

	/* Lock in normal mode */
	reset_common_data(0, 0);
	TEST_SUCC(secdata_kernel_lock(ctx),
		  "secdata_kernel_lock(), success (locked)");
	TEST_STR_EQ(mock_calls,
		    "TlclLockPhysicalPresence()\n",
		    "  tlcl calls");

	/* Lock after already locked (only one TlclLockPhysicalPresence). */
	reset_common_data(0, 0);
	TEST_SUCC(secdata_kernel_lock(ctx),
		  "secdata_kernel_lock(), lock first run");
	TEST_SUCC(secdata_kernel_lock(ctx),
		  "secdata_kernel_lock(), already locked");
	TEST_STR_EQ(mock_calls,
		    "TlclLockPhysicalPresence()\n",
		    "  tlcl calls");
}

/****************************************************************************/
/* Tests for fwmp space functions */

static void secdata_fwmp_tests(void)
{
	/* Read failure */
	reset_common_data(1, TPM_E_IOERROR);
	TEST_EQ(secdata_fwmp_read(ctx), TPM_E_IOERROR,
		"secdata_fwmp_read(), failure");
	TEST_STR_EQ(mock_calls,
		    "TlclRead(0x100a, 40)\n",
		    "  tlcl calls");
	TEST_EQ(ctx->flags & VB2_CONTEXT_NO_SECDATA_FWMP, 0,
		"  should leave NO_SECDATA_FWMP context flag");

	/* Normal read, bad CRC */
	reset_common_data(0, 0);
	mock_bad_crc = 1;
	TEST_EQ(secdata_fwmp_read(ctx), TPM_E_CORRUPTED_STATE,
		"secdata_fwmp_read(), success, bad CRC");
	TEST_STR_EQ(mock_calls,
		    "TlclRead(0x100a, 40)\n",
		    "  tlcl calls");
	TEST_EQ(ctx->flags & VB2_CONTEXT_NO_SECDATA_FWMP, 0,
		"  should leave NO_SECDATA_FWMP context flag");

	/* Normal read */
	reset_common_data(0, 0);
	TEST_SUCC(secdata_fwmp_read(ctx),
		  "secdata_fwmp_read(), success");
	TEST_STR_EQ(mock_calls,
		    "TlclRead(0x100a, 40)\n",
		    "  tlcl calls");
	TEST_EQ(memcmp(ctx->secdata_fwmp, &mock_fwmp,
		       mock_fwmp_real_size), 0, "  data");
	TEST_EQ(ctx->flags & VB2_CONTEXT_NO_SECDATA_FWMP, 0,
		"  should leave NO_SECDATA_FWMP context flag");

	/* Read error */
	reset_common_data(1, TPM_E_IOERROR);
	TEST_EQ(secdata_fwmp_read(ctx), TPM_E_IOERROR,
		"secdata_fwmp_read(), error");
	TEST_STR_EQ(mock_calls,
		    "TlclRead(0x100a, 40)\n",
		    "  tlcl calls");
	TEST_EQ(ctx->flags & VB2_CONTEXT_NO_SECDATA_FWMP, 0,
		"  should leave NO_SECDATA_FWMP context flag");

	/* Not present isn't an error; just sets context flag */
	reset_common_data(1, TPM_E_BADINDEX);
	TEST_SUCC(secdata_fwmp_read(ctx), "secdata_fwmp_read(), not present");
	TEST_STR_EQ(mock_calls,
		    "TlclRead(0x100a, 40)\n",
		    "  tlcl calls");
	TEST_NEQ(ctx->flags & VB2_CONTEXT_NO_SECDATA_FWMP, 0,
		 "  should set NO_SECDATA_FWMP context flag");

	/* Struct size too large, then bad CRC */
	reset_common_data(0, 0);
	mock_fwmp_real_size += 4;
	mock_bad_crc = 1;
	TEST_EQ(secdata_fwmp_read(ctx), TPM_E_CORRUPTED_STATE,
		  "secdata_fwmp_read(), bigger, bad CRC");
	TEST_STR_EQ(mock_calls,
		    "TlclRead(0x100a, 40)\n"
		    "TlclRead(0x100a, 44)\n",
		    "  tlcl calls");
	TEST_EQ(ctx->flags & VB2_CONTEXT_NO_SECDATA_FWMP, 0,
		"  should leave NO_SECDATA_FWMP context flag");

	/* Struct size too large */
	reset_common_data(0, 0);
	mock_fwmp_real_size += 4;
	TEST_SUCC(secdata_fwmp_read(ctx), "secdata_fwmp_read(), bigger");
	TEST_STR_EQ(mock_calls,
		    "TlclRead(0x100a, 40)\n"
		    "TlclRead(0x100a, 44)\n",
		    "  tlcl calls");
	TEST_EQ(memcmp(ctx->secdata_fwmp, &mock_fwmp,
		       mock_fwmp_real_size), 0, "  data");
	TEST_EQ(ctx->flags & VB2_CONTEXT_NO_SECDATA_FWMP, 0,
		"  should leave NO_SECDATA_FWMP context flag");
}

int main(int argc, char* argv[])
{
	misc_tests();
	secdata_firmware_tests();
	secdata_kernel_tests();
	secdata_fwmp_tests();

	return gTestSuccess ? 0 : 255;
}
