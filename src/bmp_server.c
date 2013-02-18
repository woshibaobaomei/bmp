#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "bmp_util.h"
#include "bmp_timer.h"
#include "bmp_server.h"
#include "bmp_client.h"
#include "bmp_control.h"
#include "bmp_command.h"

static bmp_server server;

/*
 * accept() connections from a server socket fd and create new client structs
 */  
static int 
bmp_accept_clients(bmp_server *server, int events)
{
    int fd, rc;
    struct sockaddr caddr;
    socklen_t slen;

    while (1) {

        slen = sizeof(caddr);

        fd = accept(server->fd, &caddr, &slen); 

        if (fd < 0) {

            if (errno == EAGAIN || errno == EWOULDBLOCK) break;

            bmp_log("accept() failed: %s", strerror(errno));

        } else {

            rc = bmp_client_create(server, fd, &caddr, slen);
        }
    }
  
    return rc;
}


static int 
bmp_server_timer_process(bmp_server *server, int timer)
{
    int rc;

    BMP_TIMER_READ(timer, rc);

    return rc;
}


static void
bmp_server_exit(int signo)
{
    close(server.control);
    
    exit(1);
}


int 
bmp_server_init(int port, int timer, int interactive)
{
    int rc = 0;
    struct epoll_event ev;
    struct sockaddr_in saddr;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT,  bmp_server_exit);
    signal(SIGTERM, bmp_server_exit);
 

    memset(&server, 0, sizeof(bmp_server));

    server.port = port;

    memset(&saddr, 0, sizeof(saddr)); 
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(server.port);

    server.fd = socket(AF_INET, SOCK_STREAM, 0);
    
    if (server.fd < 0) {
        bmp_log("socket() failed: %s", strerror(errno));
        exit(1);
    }

    rc = so_reuseaddr(server.fd);

    if (rc < 0) {
        return rc;
    }

    rc = bind(server.fd, (struct sockaddr *) &saddr, sizeof(saddr));

    if (rc < 0) {
        bmp_log("bind() failed: %s", strerror(errno));
        return rc;
    }
 
    rc = listen(server.fd, BMP_CLIENT_MAX);

    if (rc < 0) {
        bmp_log("listen() failed: %s", strerror(errno));
        return rc;
    }
    
    rc = fd_nonblock(server.fd);

    if (rc < 0) {
        return rc;
    }
 
    server.eq = epoll_create(BMP_CLIENT_MAX);

    if (server.eq < 0) {
        bmp_log("epoll_create1() failed: %s", strerror(errno));
        return -1;
    }

    ev.data.fd = server.fd;
    ev.events = EPOLLIN | EPOLLET;
   
    rc = epoll_ctl(server.eq, EPOLL_CTL_ADD, server.fd, &ev);

    if (rc < 0) {
        bmp_log("epoll_ctl(server->fd) failed: %s", strerror(errno));
        return rc;
    }

    /*
     * Register the read-end of the timer pipe with the server's epoll queue
     */
    server.timer = timer;
    ev.data.fd = server.timer;
    ev.events = EPOLLIN | EPOLLET;

    rc = epoll_ctl(server.eq, EPOLL_CTL_ADD, server.timer, &ev);

    if (rc < 0) {
        bmp_log("server timer listen error: %s", timer, strerror(errno));
        return rc;
    }

    server.ev = calloc(BMP_CLIENT_MAX, sizeof(ev));

    if (server.ev == NULL) {
        bmp_log("calloc(server->ev) failed");
        return -1;
    }

    avl_compare_fn bmp_client_compare[BMP_CLIENT_AVL] = {
        bmp_client_fd_compare,
        bmp_client_addr_compare,
    };

    server.clients = avl_multi_init(bmp_client_compare, NULL, BMP_CLIENT_AVL, 0);

    /* 
     * Always start the non-interactive control channel (loopback socket)
     */
    rc = server.control = bmp_command_init(&server, 0);

    if (rc < 0) {

    }

    /*
     * If we are interactive start the interactive control channel also (stdin)
     */
    if (interactive) {
        rc = bmp_command_init(&server, 1);
    }

    if (rc < 0) {

    }
 
    return 0;
}


int 
bmp_server_run(int timer)
{
    int i, e, n, fd;

    while (1) {
        /*
         * Main blocking call
         */
        n = epoll_wait(server.eq, server.ev, BMP_CLIENT_MAX, -1);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                bmp_log("epoll_wait error: %s", strerror(errno));
                return -1;
            }
        }

        for (i = 0; i < n; i++) {
  
            e = server.ev[i].events; 
            fd = server.ev[i].data.fd;

            if ((e & EPOLLERR) || (e & EPOLLHUP)) {
                /*
                 * Error
                 */
                continue;
            } 

            if (fd == server.fd) { // server's listen socket - accept clients

                bmp_accept_clients(&server, e);

            } else if (fd == STDIN_FILENO) { // process commands

                bmp_command_process(&server, fd, e);

            } else if (fd == server.control) { // process commands

                bmp_command_process(&server, fd, e);

            } else if (fd == server.timer) { // periodic timer

                bmp_server_timer_process(&server, timer);

            } else { // process client events

                bmp_client_process(&server, fd, e);

            }
        }
    }

    close(server.fd);
    close(server.eq);
    free(server.ev);

    return 0;
}   

