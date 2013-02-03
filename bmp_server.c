#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <fcntl.h>
#include <errno.h>
#include <termios.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "bmp_server.h"
#include "bmp_client.h"
#include "bmp_command.h"

int
bmp_log(const char *format, ...) 
{
    char log[1024];
    char ts[64];
    char *t = ts;
    char *p = log;
    struct timeval tv; 
    struct tm *tm;
    static int init = 1;

    gettimeofday(&tv, NULL);
    tm = localtime(&tv.tv_sec);
    t += strftime(t, sizeof(ts), "%H:%M:%S.", tm);
    snprintf(t, sizeof(ts), "%03ld", tv.tv_usec/1000);

    va_list args;
    va_start(args, format);

    p += snprintf(p, sizeof(log), "BMP# [%s] ", ts);
    p += vsnprintf(p, sizeof(log)-(p-log), format, args);

    va_end(args);

    printf("%s%s%s", init ? "" : "\n", log, init ? "\n" : "");
    fflush(stdout);
   
    if (init) bmp_command_prompt();

    init = 0;

    return 0;
}


int 
bmp_so_nonblock(int fd)
{
    int flags, rc;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        bmp_log("fcntl(%d, F_GETFL) failed: %s", fd, strerror(errno));
        return -1;
    }

    flags |= O_NONBLOCK;
    rc = fcntl(fd, F_SETFL, flags);
    if (rc < 0) {
        bmp_log("fcntl(%d, F_SETFL) failed: %s", fd, strerror(errno));
        return -1;
    }

    return 0;
}


int 
bmp_so_reuseaddr(int fd)
{
    int rc, optv;

    rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optv, sizeof(optv));

    if (rc < 0) {
        bmp_log("SO_REUSEADDR(%d) failed: %s", fd, strerror(errno));
    }

    return rc;
}


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
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            bmp_log("accept() failed: %s", strerror(errno));
            break;
        }

        rc = bmp_client_create(server, fd);
    }
  
    return rc;
}


int 
bmp_server_init(bmp_server *server, int port)
{
    int rc = 0;
    struct epoll_event ev;
    struct sockaddr_in saddr;

    server->port = port;

    memset(&saddr, 0, sizeof(saddr)); 
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(server->port);

    server->fd = socket(AF_INET, SOCK_STREAM, 0);
    
    if (server->fd < 0) {
        bmp_log("socket() failed: %s", strerror(errno));
        exit(1);
    }

    rc = bmp_so_reuseaddr(server->fd);

    if (rc < 0) {
        return rc;
    }

    rc = bind(server->fd, (struct sockaddr *) &saddr, sizeof(saddr));

    if (rc < 0) {
        bmp_log("bind() failed: %s", strerror(errno));
        return rc;
    }
 
    rc = listen(server->fd, BMP_CLIENT_MAX);

    if (rc < 0) {
        bmp_log("listen() failed: %s", strerror(errno));
        return rc;
    }
    
    rc = bmp_so_nonblock(server->fd);

    if (rc < 0) {
        return rc;
    }
 
    server->eq = epoll_create1(0);

    if (server->eq < 0) {
        bmp_log("epoll_create1() failed: %s", strerror(errno));
        return -1;
    }

    ev.data.fd = server->fd;
    ev.events = EPOLLIN | EPOLLET;
   
    rc = epoll_ctl(server->eq, EPOLL_CTL_ADD, server->fd, &ev);

    if (rc < 0) {
        bmp_log("epoll_ctl(server->fd) failed: %s", strerror(errno));
        return rc;
    }

    server->ev = calloc(BMP_CLIENT_MAX, sizeof(ev));

    if (server->ev == NULL) {
        bmp_log("calloc(server->ev) failed");
        return -1;
    }

    server->nclient = 0;
    memset(server->clients, 0, BMP_CLIENT_MAX*sizeof(bmp_client *));
 
    return rc;
}


int 
bmp_server_run(bmp_server *server)
{
    int i, e, n, fd;

    bmp_log("Listening on port: %d", server->port);
 
    while (1) {
        /*
         * Main blocking call
         */
        n = epoll_wait(server->eq, server->ev, BMP_CLIENT_MAX, -1);

        for (i = 0; i < n; i++) {
  
            e = server->ev[i].events; 
            fd = server->ev[i].data.fd;

            if ((e & EPOLLERR) || (e & EPOLLHUP)) {
                /*
                 * Error
                 */
                continue;
            } 
 
            if (fd == server->fd) {

                bmp_accept_clients(server, e);

            } else if (fd == STDIN_FILENO) {

                bmp_command_process(server, e);

            } else {
                /*
                 * We are processing client connections in the same thread as 
                 * the main server thread
                 */
                bmp_client_process(server, fd, e);
            } 
        }
    }

    close(server->fd);
    close(server->eq);
    free(server->ev);
}    


int main(int argc, char *argv[])
{
    int rc = 0;
    bmp_server server;

    rc = bmp_server_init(&server, 1111);

    if (rc == 0) {
        rc = bmp_command_init(&server);
    }

    if (rc == 0) {
        rc = bmp_server_run(&server);
    }

    bmp_log("Exit\n");

    return 0;
}
            


            


