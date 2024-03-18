/*
  Copyright (C) 2012 Joseph J. Pfeiffer, Jr., Ph.D. <pfeiffer@cs.nmsu.edu>

  This program can be distributed under the terms of the GNU GPLv3.
  See the file COPYING.
*/

#ifndef _LOG_H_
#define _LOG_H_
#include <stdio.h>

FILE *log_open(void);
void log_msg(const char *format, ...);
int log_error(const char *func);

#endif
