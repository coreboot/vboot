# Copyright 2026 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Library of handy test functions.
TESTLIB = ${BUILD}/tests/test.a

TEST_COMMON_DIR = tests/common
TESTLIB_SRCS += $(wildcard $(TEST_COMMON_DIR)/*.c)
TESTLIB_SRCS += tests/crc32_test.c
TESTLIB_OBJS = ${TESTLIB_SRCS:%.c=${BUILD}/%.o}

# Compiled tests.
TEST_NAMES = \
	tests/cbfstool_tests \
	tests/cgptlib_test \
	tests/chromeos_config_tests \
	tests/gpt_misc_tests \
	tests/sha_benchmark \
	tests/subprocess_tests \
	tests/verify_kernel

ifeq ($(filter-out 0,${MOCK_TPM})$(filter-out 0,${TPM2_MODE}),)
TEST_NAMES += tests/tlcl_tests
endif

TEST_FUTIL_NAMES = \
	tests/futility/binary_editor \
	tests/futility/test_file_types \
	tests/futility/test_not_really

ifneq ($(filter-out 0,${USE_FLASHROM}),)
TEST_FUTIL_NAMES += \
	tests/futility/test_misc \
	tests/futility/test_updater_utils \
	tests/futility/test_updater_utils_servo
endif

TEST_NAMES += ${TEST_FUTIL_NAMES}

TEST2X_NAMES = \
	tests/vb2_api_tests \
	tests/vb2_auxfw_sync_tests \
	tests/vb2_common_tests \
	tests/vb2_common2_tests \
	tests/vb2_common3_tests \
	tests/vb2_crypto_tests \
	tests/vb2_ec_sync_tests \
	tests/vb2_firmware_tests \
	tests/vb2_gbb_init_tests \
	tests/vb2_gbb_tests \
	tests/vb2_host_key_tests \
	tests/vb2_host_nvdata_flashrom_tests \
	tests/vb2_inject_kernel_subkey_tests \
	tests/vb2_kernel_tests \
	tests/vb2_keyblock_hash_tests \
	tests/vb2_load_kernel_tests \
	tests/vb2_load_kernel2_tests \
	tests/vb2_misc_tests \
	tests/vb2_misc2_tests \
	tests/vb2_nvstorage_tests \
	tests/vb2_rsa_padding_tests \
	tests/vb2_rsa_utility_tests \
	tests/vb2_recovery_reasons_tests \
	tests/vb2_secdata_firmware_tests \
	tests/vb2_secdata_fwmp_tests \
	tests/vb2_secdata_kernel_tests \
	tests/vb2_sha_api_tests \
	tests/vb2_sha_tests \
	tests/vb2_verify_fw \
	tests/vb20_api_kernel_tests \
	tests/hmac_test

ifeq ($(filter-out 0,${USE_FLASHROM}),)
TEST2X_NAMES += tests/vb2_host_flashrom_tests
endif

ifneq ($(filter-out 0,${USE_AVB}),)
TEST2X_NAMES += \
	tests/vb2_avb_tests \
	tests/vb2_load_android_tests
endif

TEST21_NAMES = \
	tests/vb21_host_common2_tests \
	tests/vb21_host_common_tests \
	tests/vb21_host_key_tests \
	tests/vb21_host_misc_tests \
	tests/vb21_host_sig_tests

TEST_NAMES += ${TEST2X_NAMES} ${TEST21_NAMES}

ifeq (${ARCH}, x86_64)
DUT_TEST_NAMES += tests/vb2_sha256_x86_tests
endif

HWCRYPTO_RSA_TESTS = \
	tests/vb2_hwcrypto_rsa_padding_tests \
	tests/vb2_hwcrypto_verify_fw

TEST_NAMES += ${DUT_TEST_NAMES}

ifeq (${ENABLE_HWCRYPTO_RSA_TESTS},1)
TEST2X_NAMES += ${HWCRYPTO_RSA_TESTS}
endif

ifeq ($(filter-out 0,${TPM2_MODE}),)
TLCL_TEST_NAMES = \
	tests/tpm_lite/tpmtest_earlyextend \
	tests/tpm_lite/tpmtest_earlynvram \
	tests/tpm_lite/tpmtest_earlynvram2 \
	tests/tpm_lite/tpmtest_enable \
	tests/tpm_lite/tpmtest_fastenable \
	tests/tpm_lite/tpmtest_globallock \
	tests/tpm_lite/tpmtest_redefine_unowned \
	tests/tpm_lite/tpmtest_spaceperm \
	tests/tpm_lite/tpmtest_testsetup \
	tests/tpm_lite/tpmtest_timing \
	tests/tpm_lite/tpmtest_writelimit
else
TLCL_TEST_NAMES =
endif

TEST_NAMES += ${TLCL_TEST_NAMES}

TEST_BINS = $(addprefix ${BUILD}/,${TEST_NAMES})
TEST_OBJS += $(addsuffix .o,${TEST_BINS}) ${TESTLIB_OBJS}

TEST_FUTIL_BINS = $(addprefix ${BUILD}/,${TEST_FUTIL_NAMES})
TEST2X_BINS = $(addprefix ${BUILD}/,${TEST2X_NAMES})
TEST21_BINS = $(addprefix ${BUILD}/,${TEST21_NAMES})
DUT_TEST_BINS = $(addprefix ${BUILD}/,${DUT_TEST_NAMES})

# Directory containing test keys
TEST_KEYS = ${SRC_RUN}/tests/testkeys

# Fuzzing binaries
FUZZ_TEST_NAMES = \
	tests/cgpt_fuzzer \
	tests/vb2_keyblock_fuzzer \
	tests/vb2_preamble_fuzzer

FUZZ_TEST_BINS = $(addprefix ${BUILD}/,${FUZZ_TEST_NAMES})

# Rules for tests
${TEST_BINS}: ${UTILLIB} ${TESTLIB}
${TEST_BINS}: INCLUDES += -Itests
${TEST_BINS}: LIBS = ${TESTLIB} ${UTILLIB}

${TEST_FUTIL_BINS}: ${FUTIL_OBJS} ${UTILLIB}
${TEST_FUTIL_BINS}: INCLUDES += -Ifutility
${TEST_FUTIL_BINS}: OBJS += ${FUTIL_OBJS} ${UTILLIB}
${TEST_FUTIL_BINS}: LDLIBS += ${FUTIL_LIBS}

${TEST2X_BINS}: ${FWLIB}
${TEST2X_BINS}: LIBS += ${FWLIB}

${TEST21_BINS}: LDLIBS += ${CRYPTO_LIBS}

${BUILD}/tests/%: LDLIBS += -lrt -luuid
${BUILD}/tests/%: LIBS += ${TESTLIB}

ifeq ($(filter-out 0,${TPM2_MODE}),)
TLCL_TEST_BINS = $(addprefix ${BUILD}/,${TLCL_TEST_NAMES})
${TLCL_TEST_BINS}: OBJS += ${BUILD}/tests/tpm_lite/tlcl_tests.o
${TLCL_TEST_BINS}: ${BUILD}/tests/tpm_lite/tlcl_tests.o
TEST_OBJS += ${BUILD}/tests/tpm_lite/tlcl_tests.o
endif

${TESTLIB}: ${TESTLIB_OBJS}
	@${PRINTF} "    RM            $(subst ${BUILD}/,,$@)\n"
	${Q}rm -f $@
	@${PRINTF} "    AR            $(subst ${BUILD}/,,$@)\n"
	${Q}ar qcT $@ $^

${BUILD}/tests/vb2_host_key_tests: LDLIBS += ${CRYPTO_LIBS}
${BUILD}/tests/vb2_common2_tests: LDLIBS += ${CRYPTO_LIBS}
${BUILD}/tests/vb2_common3_tests: LDLIBS += ${CRYPTO_LIBS}
${BUILD}/tests/verify_kernel: LDLIBS += ${CRYPTO_LIBS}
${BUILD}/tests/hmac_test: LDLIBS += ${CRYPTO_LIBS}

# Test runner rules
.PHONY: tests runtests rununittests runtestscripts runfutiltests runcgpttests runmisctests run2tests runfutiltestscripts

tests: ${TEST_BINS}

runtests: rununittests runtestscripts runfutiltests
	${Q}echo -e "\nruntests: \E[32;1mALL TESTS PASSED SUCCESSFULLY!\E[0;m\n"

rununittests: runcgpttests runmisctests run2tests

runcgpttests: install_for_test
	${RUNTEST} ${BUILD_RUN}/tests/cgptlib_test

runtestscripts: install_for_test ${HOSTLIB_DEF} ${HOSTLIB_UNDEF}
	${RUNTEST} ${SRC_RUN}/scripts/image_signing/sign_android_unittests.sh
	${RUNTEST} ${SRC_RUN}/scripts/image_signing/sign_uefi_unittest.py
	${RUNTEST} $(SRC_RUN)/scripts/image_signing/lib/generate_android_cloud_config_unittest.py
	${RUNTEST} ${SRC_RUN}/tests/load_kernel_tests.sh
	${RUNTEST} ${SRC_RUN}/tests/run_cgpt_tests.sh ${BUILD_RUN}/cgpt/cgpt
	${RUNTEST} ${SRC_RUN}/tests/run_cgpt_tests.sh ${BUILD_RUN}/cgpt/cgpt -D 358400
	${RUNTEST} ${SRC_RUN}/tests/run_preamble_tests.sh
	${RUNTEST} ${SRC_RUN}/tests/run_vbutil_kernel_arg_tests.sh
	${RUNTEST} ${SRC_RUN}/tests/run_vbutil_tests.sh
	${RUNTEST} ${SRC_RUN}/tests/swap_ec_rw_tests.sh
	${RUNTEST} ${SRC_RUN}/tests/vb2_rsa_tests.sh
	${RUNTEST} ${SRC_RUN}/tests/vb2_firmware_tests.sh
	${RUNTEST} ${SRC_RUN}/tests/vhost_reference.sh ${HOSTLIB_DEF} ${HOSTLIB_UNDEF}

runmisctests: install_for_test
	${RUNTEST} ${BUILD_RUN}/tests/cbfstool_tests
	${RUNTEST} ${BUILD_RUN}/tests/gpt_misc_tests
	${RUNTEST} ${BUILD_RUN}/tests/subprocess_tests
ifeq ($(filter-out 0,${MOCK_TPM})$(filter-out 0,${TPM2_MODE}),)
	${RUNTEST} ${BUILD_RUN}/tests/tlcl_tests
endif

run2tests: install_for_test
	${RUNTEST} ${BUILD_RUN}/tests/vb2_api_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb2_auxfw_sync_tests
ifneq ($(filter-out 0,${USE_AVB}),)
	${RUNTEST} ${BUILD_RUN}/tests/vb2_avb_tests ${TEST_KEYS}
	${RUNTEST} ${BUILD_RUN}/tests/vb2_load_android_tests
endif
	${RUNTEST} ${BUILD_RUN}/tests/vb2_common_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb2_common2_tests ${TEST_KEYS}
	${RUNTEST} ${BUILD_RUN}/tests/vb2_common3_tests ${TEST_KEYS}
	${RUNTEST} ${BUILD_RUN}/tests/vb2_crypto_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb2_ec_sync_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb2_firmware_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb2_gbb_init_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb2_gbb_tests
ifeq ($(filter-out 0,${USE_FLASHROM}),)
	${RUNTEST} ${BUILD_RUN}/tests/vb2_host_flashrom_tests
endif
	${RUNTEST} ${BUILD_RUN}/tests/vb2_host_key_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb2_host_nvdata_flashrom_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb2_inject_kernel_subkey_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb2_load_kernel_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb2_load_kernel2_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb2_kernel_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb2_keyblock_hash_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb2_misc_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb2_misc2_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb2_nvstorage_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb2_recovery_reasons_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb2_rsa_utility_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb2_secdata_firmware_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb2_secdata_fwmp_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb2_secdata_kernel_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb2_sha_api_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb2_sha_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb20_api_kernel_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb21_host_common_tests
	${RUNTEST} ${BUILD_RUN}/tests/vb21_host_common2_tests ${TEST_KEYS}
	${RUNTEST} ${BUILD_RUN}/tests/vb21_host_key_tests ${TEST_KEYS} ${BUILD_RUN}
	${RUNTEST} ${BUILD_RUN}/tests/vb21_host_misc_tests ${BUILD_RUN}
	${RUNTEST} ${BUILD_RUN}/tests/vb21_host_sig_tests ${TEST_KEYS}

runfutiltestscripts: install_for_test
	${RUNTEST} ${SRC_RUN}/tests/futility/run_test_scripts.sh

runfutiltests: install_for_test runfutiltestscripts
	${RUNTEST} ${BUILD_RUN}/tests/futility/test_file_types
	${RUNTEST} ${BUILD_RUN}/tests/futility/test_not_really
ifneq ($(filter-out 0,${USE_FLASHROM}),)
	${RUNTEST} ${BUILD_RUN}/tests/futility/test_misc
	${RUNTEST} ${BUILD_RUN}/tests/futility/test_updater_utils
	${RUNTEST} ${BUILD_RUN}/tests/futility/test_updater_utils_servo
endif
	rm -rf ${SRC_RUN}/tests/futility/data_copy

.PHONY: install_dut_test
install_dut_test: ${DUT_TEST_BINS}
ifneq ($(strip ${DUT_TEST_BINS}),)
	@${PRINTF} "    INSTALL       DUT TESTS\n"
	${Q}mkdir -p ${DUT_TEST_DIR}
	${Q}${INSTALL} -t ${DUT_TEST_DIR} $^
endif

.PHONY: fuzzers
fuzzers: ${FUZZ_TEST_BINS}

${FUZZ_TEST_BINS}: ${FWLIB}
${FUZZ_TEST_BINS}: LIBS = ${FWLIB}
${FUZZ_TEST_BINS}: LDFLAGS += -fsanitize=fuzzer
