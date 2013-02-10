#ifndef __BMP_COMMAND_H__
#define __BMP_COMMAND_H__

#include "bmp_server.h"


int bmp_command_init(bmp_server *server, int interactive);
int bmp_command_process(bmp_server *server, int fd, int events);


#endif
