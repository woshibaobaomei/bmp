#ifndef __BMP_TIMER_H__
#define __BMP_TIMER_H__

#include "bmp_server.h"

#define BMP_TIMER_INTERVAL 2

#define BMP_TIMER_READ(tm, rc) do {  \
    char buf[64];                    \
    rc = read(tm, buf, sizeof(buf)); \
} while (0)


int bmp_timer_init(bmp_server *server);

#endif
