/*-----------------------------------------------------------------------------
 * bmp.c - BGP Monitoring Protocol server
 *
 * Notes: Linux only
 *-----------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#define LISTEN_BACKLOG 4096
#define EPOLL_MAX      16384

#define epev struct epoll_event

/*
 * The bmp_server type is simply a socket (fd) listening on a (port) and an 
 * associated epoll descriptor / queue (eq) that notifies the code when events
 * arrive on the listening socket (and possibly any client sockets)
 */
typedef struct bmp_server_ {
    int   fd;
    int   eq;
    epev *ev;
    short port;
    int   flags;
    int   index;
} bmp_server;
 
/*
 * The bmp_client type represents a BGP speaker that has connected to us and 
 * is sending us data about its connected peers (the BGP updates it is getting 
 * from its connected peers)
 */
typedef struct bmp_client_ {
    int  fd;
    char rdbuf[0];
    


} bmp_client;


static char buf[128000];
static uint64_t total = 0;


void
bmp_io_read(bmp_server *server, int fd)
{
    char *rdptr;

    // if the client has some partial PDU sitting in its temp buffer, copy 
    // that over to the head of the global read buffer, and start filling
    // up the global read buffer from that point on

    // read from net

    // feed protocol

    // if there is some partial PDU left, copy it over to client temp buffer    

}

int
bmp_process_client(bmp_server *server, int fd, int events)
{
    int rc = 0;
    struct epoll_event ev;
    struct sockaddr caddr;
    socklen_t slen;  
     
    while (1) {

        rc = read(fd, buf, sizeof(buf));

        if (rc > 0) {

            total += rc;

        } else if (rc == 0) {

            fprintf(stdout, "read(%d) remote close\n", fd);
            close(fd);
            break;

        } else {

            if (errno != EAGAIN) {
                fprintf(stdout, "read(%d) failed\n", fd);
                close(fd);
            }

            break;
        }
    } 
}


int 
bmp_so_nonblock(int fd)
{
    int flags, rc;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        fprintf(stdout, "fcntl(F_GETFL) failed: %s\n", strerror(errno));
        return -1;
    }

    flags |= O_NONBLOCK;
    rc = fcntl(fd, F_SETFL, flags);
    if (rc < 0) {
        fprintf(stdout, "fcntl(F_SETFL) failed: %s\n", strerror(errno));
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
        fprintf(stdout, "SO_REUSEADDR failed: %s\n", strerror(errno));
    }

    return rc;
}


/* 
 * Queue the accepted fd to the same epoll queue as the server socket
 */
static int
bmp_queue_client(bmp_server *server, int fd)
{
    int rc;
    struct epoll_event ev;

    rc = bmp_so_nonblock(fd);
 
    if (rc < 0) {
        return rc;
    }
 
    ev.data.fd = fd;
    ev.events = EPOLLIN | EPOLLET;
    rc = epoll_ctl(server->eq, EPOLL_CTL_ADD, fd, &ev);  
 
    if (rc < 0) {
        fprintf(stdout, "epoll_ctl(+fd) failed: %s\n", strerror(errno));
    }
}


/*
 * accept() connections from a server socket fd (sfd) and queue them somewhere
 */  
int 
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
            fprintf(stdout, "accept() failed: %s\n", strerror(errno));
            break;
        }

        rc = bmp_queue_client(server, fd);
    }
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
        fprintf(stdout, "socket() failed: %s\n", strerror(errno));
        exit(1);
    }

    rc = bmp_so_reuseaddr(server->fd);

    if (rc < 0) {
        return rc;
    }

    rc = bind(server->fd, (struct sockaddr *) &saddr, sizeof(saddr));

    if (rc < 0) {
        fprintf(stdout, "bind() failed: %s\n", strerror(errno));
        return rc;
    }
 
    rc = listen(server->fd, LISTEN_BACKLOG);

    if (rc < 0) {
        fprintf(stdout, "listen() failed: %s\n", strerror(errno));
        return rc;
    }
    
    rc = bmp_so_nonblock(server->fd);

    if (rc < 0) {
        return rc;
    }
 
    server->eq = epoll_create1(0);

    if (server->eq < 0) {
        fprintf(stdout, "epoll_create1() failed: %s\n", strerror(errno));
        return -1;
    }

    ev.data.fd = server->fd;
    ev.events = EPOLLIN | EPOLLET;
   
    rc = epoll_ctl(server->eq, EPOLL_CTL_ADD, server->fd, &ev);

    if (rc < 0) {
        fprintf(stdout, "epoll_ctl(+sfd) failed: %s\n", strerror(errno));
        return rc;
    }

    server->ev = calloc(EPOLL_MAX, sizeof(ev));

    if (server->ev == NULL) {
        fprintf(stdout, "calloc(EPOLL_MAX) failed\n");
        return -1;
    }
 
    return rc;
}


int 
bmp_server_run(bmp_server *server)
{
    int i, e, n, fd;

    fprintf(stdout, "Listening on [%d]\n", server->port);

    while (1) {
        /*
         * Main blocking call
         */
        n = epoll_wait(server->eq, server->ev, EPOLL_MAX, -1);

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

            } else {
                /*
                 * We are processing client connections in the same thread as 
                 * the main server thread
                 */
                bmp_process_client(server, fd, e);
            } 
        }
    }

    close(server->fd);
    close(server->eq);
    free(server->ev);
}    


int main(int argc, char *argv[])
{
    bmp_server server;

    bmp_console_run();

    bmp_server_init(&server, 1111);

    bmp_server_run(&server);

    return 0;
}
            


            


