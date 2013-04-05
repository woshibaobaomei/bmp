#ifndef __BMP_SERVER_H__
#define __BMP_SERVER_H__

#include <stdint.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/time.h>
#include "avl.h"

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
    int  pid;
    int  port;
    int  timer;
 
    uint32_t  flags;
    uint64_t  bytes;
    uint64_t  msgs;
    uint64_t  memory;
    uint32_t  peers;
    struct timeval time;
    avl_tree *sessions;
};


int bmp_server_init(int port, int interactive);
int bmp_server_run();

int bmp_show_summary();
 
#endif
