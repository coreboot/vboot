/*
 * Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "futility.h"

/* #define DEBUG 1 */
#ifdef DEBUG
#define debug(args...) printf(args)
#else
#define debug(args...)
#endif

#define MYNAME "futility"
#define SUBDIR "old_bins"

static const char * const usage= "\n\
Usage: " MYNAME " PROGRAM|COMMAND [args...]\n\
\n\
This is the unified firmware utility, which will eventually replace\n\
all the distinct userspace tools formerly produced by the\n\
vboot_reference package.\n\
\n\
When symlinked under the name of one of those previous tools, it can\n\
do one of two things: either it will fully implement the original\n\
behavior, or (until that functionality is complete) it will just exec\n\
the original binary.\n\
\n\
In either case it may also record some usage information in /tmp to\n\
help improve coverage and correctness.\n\
\n\
If you invoke it directly instead of via a symlink, it requires one\n\
argument, which is the name of the old binary to exec. That binary\n\
must be located in a directory named \"" SUBDIR "\" underneath\n\
the " MYNAME " executable.\n\
\n";

static int help(int argc, char *argv[])
{
  futil_cmd_t *cmd;
  int i;

  fputs(usage, stdout);

  printf("The following commands are built-in:\n");

  for (cmd = futil_cmds_start(); cmd < futil_cmds_end(); cmd++)
    printf("  %-20s %s\n",
           cmd->name, cmd->shorthelp);

  printf("\n");

  printf("FYI, you added these args that I'm ignoring:\n");
  for (i = 0; i < argc; i++)
    printf("argv[%d] = %s\n", i, argv[i]);

  return 0;
}
DECLARE_FUTIL_COMMAND(help, help, "Show a bit of help");


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
  futil_cmd_t *cmd;

  for (i = 0; i < argc; i++)
    debug("argv[%d] = %s\n", i, argv[i]);

  /* How were we invoked? */
  progname = strrchr(argv[0], '/');
  if (progname)
    progname++;
  else
    progname = argv[0];
  debug("progname is %s\n", progname);

  /* Invoked directly by name */
  if (0 == strcmp(progname, MYNAME)) {
    if (argc < 2) {                     /* must have an argument */
      fputs(usage, stderr);
      exit(1);
    }

    /* We can just pass the rest along, then */
    argc--;
    argv++;

    /* So now what name do we want to invoke? */
    progname = strrchr(argv[0], '/');
    if (progname)
      progname++;
    else
      progname = argv[0];
    debug("now progname is %s\n", progname);
  }

  /* See if it's asking for something we know how to do ourselves */
  for (cmd = futil_cmds_start(); cmd < futil_cmds_end(); cmd++)
    if (0 == strcmp(cmd->name, progname))
      return cmd->handler(argc, argv);

  /* Nope, it must be wrapped */

  /* The old binaries live under the true executable. Find out where that is. */
  myproc = getpid();
  snprintf(buf, 80, "/proc/%d/exe", myproc);
  r = readlink(buf, truename, PATH_MAX-1);
  if (r < 0) {
    fprintf(stderr, "%s is lost: %s => %s: %s\n", MYNAME, argv[0],
            buf, strerror(errno));
    exit(1);
  }
  debug("truename is %s\n", truename);
  s = strrchr(truename, '/');           /* Find the true directory */
  if (s) {
    *s = '\0';
  } else {                              /* I don't think this can happen */
    fprintf(stderr, "%s says %s doesn't make sense\n", MYNAME, truename);
    exit(1);
  }
  /* We've allocated PATH_MAX. If the old binary path doesn't fit, it can't be
   * in the filesystem. */
  snprintf(oldname, PATH_MAX, "%s/%s/%s", truename, SUBDIR, progname);
  debug("oldname is %s\n", oldname);

  for (i = 0; i < argc; i++)
    debug("argv[%d] = %s\n", i, argv[i]);

  fflush(0);
  execve(oldname, argv, envp);

  fprintf(stderr, "%s failed to exec %s: %s\n", MYNAME,
          oldname, strerror(errno));
  return 1;
}
