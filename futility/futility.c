/*
 * Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEBUG 1
#ifdef DEBUG
#define debug(args...) printf(args)
#else
#define debug(args...)
#endif

#define MYNAME "futility"


int main(int argc, char *argv[], char *envp[])
{
  char *progname;
  char truename[PATH_MAX];
  char oldname[PATH_MAX];
  char buf[80];
  pid_t myproc;
  ssize_t r;
  char *s;
  int i;

  /* What program are we wrapping? */
  progname = strrchr(argv[0], '/');
  if (progname)
    progname++;
  else
    progname = argv[0];
  debug("progname is %s\n", progname);

  /* Invoked directly by name */
  if (0 == strcmp(progname, MYNAME)) {
    if (argc < 2) {
      fprintf(stderr, "Usage: %s PROGRAM|COMMAND [args...]\n", MYNAME);
      exit(1);
    }
    /* FIXME: Implement some functions of our own... */

    /* Going to just wrap existing utilities */
    argc--;
    argv++;

    /* FIXME: diddle argv[0] so it has the right name? */
  }

  /* The old binaries live under the true executable. Find out where that is. */
  myproc = getpid();
  snprintf(buf, 80, "/proc/%d/exe", myproc);
  r = readlink(buf, truename, PATH_MAX-1);
  if (r < 0) {
    fprintf(stderr, "%s => %s: %s\n", argv[0], buf, strerror(errno));
    exit(1);
  }
  debug("truename is %s\n", truename);
  s = strrchr(truename, '/');           /* Find the true directory */
  if (s) {
    *s = '\0';
  } else {                              /* I don't think this can happen */
    fprintf(stderr, "%s doesn't make sense\n", truename);
    exit(1);
  }
  /* We've allocated PATH_MAX. If the old binary path doesn't fit, it can't be
   * in the filesystem. */
  snprintf(oldname, PATH_MAX, "%s/old_bins/%s", truename, progname);
  debug("oldname is %s\n", oldname);

  for (i = 0; i < argc; i++)
    debug("argv[%d] = %s\n", i, argv[i]);

  execv(oldname, argv);

  fprintf(stderr, "%s failed to exec: %s\n", oldname, strerror(errno));
  return 1;
}
