/* Copyright 2011 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#ifndef VBOOT_REFERENCE_COMMON_TESTS_H_
#define VBOOT_REFERENCE_COMMON_TESTS_H_

#include <setjmp.h>
#include <stdio.h>

/* Used to get a line number as a constant string. Need to stringify it twice */
#define STRINGIFY(x)	#x
#define TOSTRING(x)	STRINGIFY(x)

/* Create a temp dir under ${BUILD_RUN}. */
const char *create_test_tmp_dir(const char *name);

extern int gTestSuccess;
extern int gTestAbortArmed;
extern jmp_buf gTestJmpEnv;

/* Return 1 if result is equal to expected_result, else return 0.
 * Also update the global gTestSuccess flag if test fails. */
int test_eq(int result, int expected,
	    const char *preamble, const char *desc, const char *comment);

#define TEST_EQ(result, expected, comment) \
	test_eq(result, expected, \
		__FILE__ ":" TOSTRING(__LINE__), \
		#result " == " #expected, \
		comment)

#define TEST_EQ_S(result, expected) TEST_EQ(result, expected, NULL);

/* Return 0 if result is equal to not_expected_result, else return 1.
 * Also update the global gTestSuccess flag if test fails. */
int test_neq(int result, int not_expected,
	     const char *preamble, const char *desc, const char *comment);

#define TEST_NEQ(result, not_expected, comment) \
	test_neq(result, not_expected, \
		 __FILE__ ":" TOSTRING(__LINE__), \
		 #result " != " #not_expected, \
		 comment)

/* Return 1 if result pointer is equal to expected_result pointer,
 * else return 0.  Does not check pointer contents, only the pointer
 * itself.  Also update the global gTestSuccess flag if test fails. */
int test_ptr_eq(const void* result, const void* expected,
		const char *preamble, const char *desc, const char *comment);

#define TEST_PTR_EQ(result, expected, comment) \
	test_ptr_eq(result, expected, \
		    __FILE__ ":" TOSTRING(__LINE__), \
		    #result " == " #expected, \
		    comment)

/* Return 1 if result pointer is not equal to expected_result pointer,
 * else return 0.  Does not check pointer contents, only the pointer
 * itself.  Also update the global gTestSuccess flag if test fails. */
int test_ptr_neq(const void* result, const void* not_expected,
		 const char *preamble, const char *desc, const char *comment);

#define TEST_PTR_NEQ(result, not_expected, comment) \
	test_ptr_neq(result, not_expected, \
		     __FILE__ ":" TOSTRING(__LINE__), \
		     #result " != " #not_expected, \
		     comment)

/* Return 1 if result string is equal to expected_result string,
 * else return 0.  Also update the global gTestSuccess flag if test fails. */
int test_str_eq(const char* result, const char* expected,
		const char *preamble, const char *desc, const char *comment);

#define TEST_STR_EQ(result, expected, comment) \
	test_str_eq(result, expected, \
		    __FILE__ ":" TOSTRING(__LINE__), \
		    #result " == " #expected, \
		    comment)

/* Return 1 if result string is not equal to not_expected string,
 * else return 0.  Also update the global gTestSuccess flag if test fails. */
int test_str_neq(const char* result, const char* not_expected,
		 const char *preamble, const char *desc, const char *comment);

#define TEST_STR_NEQ(result, not_expected, comment) \
	test_str_neq(result, not_expected, \
		     __FILE__ ":" TOSTRING(__LINE__), \
		     #result " != " #not_expected, \
		     comment)

/* Return 1 if the result is true, else return 0.
 * Also update the global gTestSuccess flag if test fails. */
int test_true(int result,
	      const char *preamble, const char *desc, const char *comment);

#define TEST_TRUE(result, comment) \
	test_true(result, \
		  __FILE__ ":" TOSTRING(__LINE__), \
		  #result " == true", \
		  comment)

/* Return 1 if the result is false, else return 0.
 * Also update the global gTestSuccess flag if test fails. */
int test_false(int result,
	       const char *preamble, const char *desc, const char *comment);

#define TEST_FALSE(result, comment) \
	test_false(result, \
		   __FILE__ ":" TOSTRING(__LINE__), \
		   #result " == false", \
		   comment)

/* Return 1 if result is 0 (VB2_SUCCESS or other), else return 0.
 * Also update the global gTestSuccess flag if test fails. */
int test_succ(int result,
	      const char *preamble, const char *desc, const char *comment);

#define TEST_SUCC(result, comment) \
	test_succ(result, \
		  __FILE__ ":" TOSTRING(__LINE__), \
		  #result " == 0", \
		  comment)

/* Return 1 if result is not 0 (VB2_SUCCESS or other), else return 1.
 * Also update the global gTestSuccess flag if test fails. */
int test_fail(int result,
	      const char *preamble, const char *desc, const char *comment);

#define TEST_FAIL(result, comment) \
	test_fail(result, \
		  __FILE__ ":" TOSTRING(__LINE__), \
		  #result " != 0", \
		  comment)

/* Return 1 if vb2ex_abort() was called, else return 0.
 * Also update the global gTestSuccess flag if test fails. */
int test_abort(int aborted,
	       const char *preamble, const char *desc, const char *comment);

#define TEST_ABORT(call, comment) do { \
	gTestAbortArmed = 1; \
	int jumped = setjmp(gTestJmpEnv); \
	if (!jumped) \
		call; \
	gTestAbortArmed = 0; \
	test_abort(jumped, \
		   __FILE__ ":" TOSTRING(__LINE__), \
		   #call " causes abort", \
		   comment); \
} while (0)

/* ANSI Color coding sequences.
 *
 * Don't use \e as MSC does not recognize it as a valid escape sequence.
 */
#define COL_GREEN "\x1b[1;32m"
#define COL_YELLOW "\x1b[1;33m"
#define COL_RED "\x1b[0;31m"
#define COL_STOP "\x1b[m"

#define die(...) \
	do { \
		fprintf(stderr, __VA_ARGS__); \
		abort(); \
	} while (0)

/* Abort if asprintf fails. */
#define xasprintf(...) \
	do { \
		if (asprintf(__VA_ARGS__) < 0) \
			abort(); \
	} while (0)

#endif  /* VBOOT_REFERENCE_COMMON_TESTS_H_ */
