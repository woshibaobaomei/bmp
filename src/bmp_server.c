#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "bmp_log.h"
#include "bmp_util.h"
#include "bmp_timer.h"
#include "bmp_table.h"
#include "bmp_server.h"
#include "bgp_router.h"
#include "bmp_control.h"
#include "bmp_command.h"
#include "bmp_session.h"
#include "bmp_process.h"

bmp_server server;

/*
 * accept() connections from a server socket fd and create new sessions
 */  
static int 
bmp_accept_sessions(bmp_server *server, int events)
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

            rc = bmp_session_create(server, fd, &caddr, slen);
        }
    }
  
    return rc;
}


static int 
bmp_server_timer_process(bmp_server *server, int timer)
{
    int rc;

    BMP_TIMER_READ(timer, rc);
    
    // XXX: nothing to really do here. TBD

    return rc;
}


static void
bmp_server_exit(int signo)
{
    exit(1);
}


int 
bmp_server_init(int port, int interactive)
{
    int rc = 0, timer;
    struct epoll_event ev;
    struct sockaddr_in saddr;

    signal(SIGPIPE, SIG_IGN);
    signal(SIGINT,  bmp_server_exit);
    signal(SIGTERM, bmp_server_exit);
 

    memset(&server, 0, sizeof(bmp_server));
 
    server.pid = getpid();
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
 
    rc = listen(server.fd, BMP_SESSION_MAX);

    if (rc < 0) {
        bmp_log("listen() failed: %s", strerror(errno));
        return rc;
    }
    
    rc = fd_nonblock(server.fd);

    if (rc < 0) {
        return rc;
    }
 
    /*
     * Create the epoll instance and register the listen socket with the server 
     * epoll queue 
     */
    server.eq = epoll_create(BMP_SESSION_MAX);

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
     * Create a timer fd and register the read-end of the timer pipe with the 
     * server's epoll queue
     */
    timer = bmp_timer_init();

    if (timer < 0) {
        bmp_log("Timer init failed");
        return -1;
    }

    server.timer = timer;
    ev.data.fd = server.timer;
    ev.events = EPOLLIN | EPOLLET;

    rc = epoll_ctl(server.eq, EPOLL_CTL_ADD, server.timer, &ev);

    if (rc < 0) {
        bmp_log("server timer listen error: %s", timer, strerror(errno));
        return rc;
    }

    /*
     * Allocate the clients event queue
     */
    server.ev = calloc(BMP_SESSION_MAX, sizeof(ev));

    if (server.ev == NULL) {
        bmp_log("calloc(server->ev) failed");
        return -1;
    }

    /* 
     * Initialize the session AVL tree
     */
    server.sessions = avl_init(bmp_session_compare, NULL, 0);

    /* 
     * Start the command processing task
     */
    rc = bmp_command_init(interactive);
    
    if (rc < 0) {
        return -1;
    }

    /*
     * Initialize the main BMP "processing" task
     */
    rc = bmp_process_init();

    if (rc < 0) {
        return -1;
    }

    /*
     * Initialize the BMP table module
     */
    rc = bmp_table_init();

    if (rc < 0) {
        return -1;
    }
 
    return rc;
}


int 
bmp_server_run()
{
    int i, ev, n, fd, rc;

    gettimeofday(&server.time, 0);

    rc = bmp_process_run();

    if (rc < 0) {
        return -1;
    }

    while (1) {
        /*
         * Main blocking call
         */
        n = epoll_wait(server.eq, server.ev, BMP_SESSION_MAX, -1);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                bmp_log("epoll_wait error: %s", strerror(errno));
                return -1;
            }
        }

        for (i = 0; i < n; i++) {
  
            ev = server.ev[i].events; 
            fd = server.ev[i].data.fd;

            if ((ev & EPOLLERR) || (ev & EPOLLHUP)) {
                /*
                 * Error
                 */
                continue;
            } 

            if (fd == server.fd) { // server's listen socket - accept sessions

                bmp_accept_sessions(&server, ev);

            } else if (fd == server.timer) { // periodic timer

                bmp_server_timer_process(&server, fd);

            } else { // session events

                bmp_session_process(&server, fd, ev);

            }
        }
    }

    close(server.fd);
    close(server.eq);
    free(server.ev);

    return 0;
}   


int
bmp_show_summary()
{
    dprintf(out, "%% TODO\n");
    return 0;
}



