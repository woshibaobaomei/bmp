#ifndef __BMP_COMMAND_H__
#define __BMP_COMMAND_H__

#include <stdio.h>
 
extern int out;
extern struct timeval now;

int bmp_command_init(int interactive);
int bmp_command_run();

#endif
