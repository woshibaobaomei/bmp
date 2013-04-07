#ifndef __BMP_CONTEXT_H__
#define __BMP_CONTEXT_H__

#include <pthread.h>
#include "bmp_table.h"

#define BMP_CONTEXT_ONLINE  0
#define BMP_CONTEXT_OFFLINE 1
#define BMP_CONTEXT_MAX     2

typedef struct bmp_context_ {
    bmp_table       bmp_table_context[BGP_AF_MAX];
    avl_tree       *bgp_routers;
    pthread_mutex_t bgp_routers_lock;
} bmp_context;


int
bmp_context_init(int context);


avl_tree *
bmp_context_routers(int context);


#endif

