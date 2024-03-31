/*
  Copyright (C) 2012 Joseph J. Pfeiffer, Jr., Ph.D. <pfeiffer@cs.nmsu.edu>

  This program can be distributed under the terms of the GNU GPLv3.
  See the file COPYING.

  Since the point of this filesystem is to learn FUSE and its
  datastructures, I want to see *everything* that happens related to
  its data structures.  This file contains macros and functions to
  accomplish this.
*/
#include <errno.h>
#include <fuse.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
struct bb_state {
    FILE *logfile;
    char *rootdir;
};
#define LOG_FILE (*((FILE **) fuse_get_context()->private_data))

#include "log.h"

FILE *log_open() {
    FILE *logfile;
    
    // very first thing, open up the logfile and mark that we got in
    // here.  If we can't open the logfile, we're dead.
    logfile = fopen("myfs.log", "w");
    if (logfile == NULL) {
	perror("logfile");
	exit(EXIT_FAILURE);
    }
    
    // set logfile to line buffering
    setvbuf(logfile, NULL, _IOLBF, 0);

    return logfile;
}

void log_msg(const char *format, ...) {
    va_list ap;
    va_start(ap, format);

    vfprintf(LOG_FILE, format, ap);
}

// Report errors to logfile and give -errno to caller
int log_error(const char *func) {
    int ret = -errno;
    
    log_msg("    ERROR %s: %s\n", func, strerror(errno));
    
    return ret;
}