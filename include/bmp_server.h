#ifndef __BMP_SERVER_H__
#define __BMP_SERVER_H__

#include <stdint.h>
#include <sys/epoll.h>
#include "bmp_client.h"

/*
 * The bmp_server type is simply a socket (fd) listening on a (port) and an 
 * associated epoll descriptor / queue (eq) that notifies the code when events
 * arrive on the listening socket (and possibly any client sockets)
 */
#define epv struct epoll_event
typedef struct bmp_server_ bmp_server;
struct bmp_server_ {
    int  fd;
    int  eq;
    epv *ev;
    int  port;
 
    uint32_t  flags;
    uint64_t  bytes;
    uint64_t  msgs;
    uint64_t  memory;
    uint32_t  peers;
    avl_tree *clients[BMP_CLIENT_AVL_MAX];
};


int bmp_server_init(bmp_server *server, int port);
int bmp_server_run(bmp_server *server, int timer);
 
#endif
