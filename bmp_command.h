#ifndef __BMP_COMMAND_H__
#define __BMP_COMMAND_H__

#include "bmp_server.h"


int bmp_command_prompt();
int bmp_console_init(bmp_server *server);
int bmp_process_console(bmp_server *server, int events);


#endif
