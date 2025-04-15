/* Copyright 2014 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

/*
 * System includes for vboot reference library.  This is the ONLY
 * place in firmware/ where system headers may be included via
 * #include <...>, so that there's only one place that needs to be
 * fixed up for platforms which don't have all the system includes.
 */

#ifndef VBOOT_REFERENCE_2SYSINCLUDES_H_
#define VBOOT_REFERENCE_2SYSINCLUDES_H_

#include <ctype.h>
#include <inttypes.h>  /* For PRIu64 */
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(__NetBSD__) || defined(__FreeBSD__) || defined(__DragonFly__)
#include <sys/endian.h>
#else
#include <endian.h>
#endif

#endif  /* VBOOT_REFERENCE_2SYSINCLUDES_H_ */
