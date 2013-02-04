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
#define epev struct epoll_event
typedef struct bmp_server_ bmp_server;
struct bmp_server_ {
    int   fd;
    int   eq;
    epev *ev;
    short port;
    int   flags;
    int   index;
 
    uint64_t    bytes;
    uint64_t    msgs;
    uint32_t    clients;
    bmp_client *client[BMP_CLIENT_MAX];
};


int bmp_server_init(bmp_server *server, int port);
int bmp_server_run(bmp_server *server);
 
#endif
