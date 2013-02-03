#ifndef __BMP_SERVER_H__
#define __BMP_SERVER_H__

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
 
    int         nclient;
    bmp_client *clients[BMP_CLIENT_MAX];
};


int bmp_log(const char *fmt, ...);

int bmp_so_nonblock(int fd);
int bmp_so_reuseaddr(int fd);

int bmp_server_init(bmp_server *server, int port);
int bmp_server_run(bmp_server *server);
 
#endif
