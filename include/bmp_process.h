#ifndef __BMP_PROCESS_H__
#define __BMP_PROCESS_H__

#include "bgp_router.h"


int bmp_process_init();
int bmp_process_run();

/*
 * Add a router to the processing queue
 */
int bmp_process_message_signal(bgp_router *router);
int bmp_process_message_consume();

#endif
