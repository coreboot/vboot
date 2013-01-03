/*
 * Copyright (c) 2013 The Chromium OS Authors. All rights reserved.
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MYNAME "futility"

/* Just point, don't modify, unlike basename(3) */
static const char *base(const char *fullpath)
{
  const char *p;
  p = strrchr(fullpath, '/');
  if (p)
    p++;
  else
    p = fullpath;
  return p;
}

int main(int argc, char *argv[], char *envp[])
{
  int i;
  const char *progname;

  for(i = 0; i < argc; i++)
    printf("[%d] = (%s)\n", i, argv[i]);

  progname = base(argv[0]);

  /* Invoked directly and told what to launch */
  if (0 == strcmp(progname, MYNAME)) {
    if (argc < 2) {
      fprintf(stderr, "%s needs some arguments\n", progname);
      return 1;
    }
    printf("KHAAAAAN!!\n");
    /* execvpe() will search PATH for the program */
    execvpe(argv[1], argv+1, envp);
    fprintf(stderr, "%s failed to exec %s: %s\n", MYNAME,
            argv[1], strerror(errno));
    return 1;
  }

  /* Invoked by another name */
  fprintf(stderr, "%s doesn't know how to pretend to be %s yet\n",
          MYNAME, progname);

  return 1;
}
