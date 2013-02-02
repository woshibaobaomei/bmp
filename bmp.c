/*-----------------------------------------------------------------------------
 * bmp.c - BGP Monitoring Protocol (BMP) server
 *
 * Notes: Linux only
 *-----------------------------------------------------------------------------
 */

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

#define BMP_CMD_MAX    (1 << 10)
#define BMP_CLIENT_MAX (1 << 10)
#define BMP_RDBUF_MAX  (1 << 16) 

#define BMP_RDBUF_SPACE(c) ((c)->rdbuf + BMP_RDBUF_MAX - (c)->rdptr)


/*
 * Forward declarations for all major types
 */
typedef struct bmp_client_ bmp_client;
typedef struct bmp_server_ bmp_server;
typedef struct bmp_message_ bmp_message;


/*
 * The bmp_client type represents a BGP speaker that has connected to us and 
 * is sending us data it receives (BGP updates) from its connected peers.  
 */
struct bmp_client_ {
    int   fd;
    char *rdptr;
    char  rdbuf[BMP_RDBUF_MAX];
        
    bmp_message *head;
    bmp_message *tail;
};


/*
 * The bmp_server type is simply a socket (fd) listening on a (port) and an 
 * associated epoll descriptor / queue (eq) that notifies the code when events
 * arrive on the listening socket (and possibly any client sockets)
 */
#define epev struct epoll_event
struct bmp_server_ {
    int   fd;
    int   eq;
    epev *ev;
    short port;
    int   flags;
    int   index;
 
    bmp_client *clients[BMP_CLIENT_MAX];
};
 

/*
 * 
 */
struct bmp_message_ {
    struct timeval time;
    bmp_message   *next;
    unsigned char  data[0];
};


void
bmp_log(const char *format, ...) 
{
    char log[1024];
    char ts[64];
    char *t = ts;
    char *p = log;
    struct timeval tv; 
    struct tm *tm;

    gettimeofday(&tv, NULL);
    tm = localtime(&tv.tv_sec);
    t += strftime(t, sizeof(ts), "%H:%M:%S.", tm);
    snprintf(t, sizeof(ts), "%03ld", tv.tv_usec/1000);

    va_list args;
    va_start(args, format);

    p += snprintf(p, sizeof(log), "BMP# [%s] ", ts);
    p += vsnprintf(p, sizeof(log)-(p-log), format, args);

    va_end(args);

    printf("\n%s", log);
    fflush(stdout);
}



static void
bmp_cleanup_client(bmp_client *client)
{


}


void
bmp_close_client(bmp_server *server, bmp_client *client, int reason)
{
    assert(client != NULL);
    assert(client->fd != 0);

    server->clients[client->fd] = NULL;


    bmp_log("BMP-ADJCHANGE: %d DN (reason: %d)", client->fd, reason);


    close(client->fd); // this will also remove the fd from the epoll queue

    bmp_cleanup_client(client);
}



char *
bmp_protocol_read(bmp_server *server,bmp_client *client,char *data,char *end)
{
 


    return data;   
}


int
bmp_net_read(bmp_server *server, bmp_client *client)
{
    int rc = 1, space;
    char *pread;

    assert(client->fd != 0);

    while (rc > 0) {

    while ((space = BMP_RDBUF_SPACE(client)) > 0) {

        rc = read(client->fd, client->rdptr, space);

        if (rc > 0) {

            client->rdptr += rc;
         
        } else if (rc == 0) {

            goto bmp_client_close;
 
        } else {

            if (errno != EAGAIN) goto bmp_read_error;
            
            break;
        }
    }    

    if (client->rdptr - client->rdbuf > 0) {
        /*
         * Whatever we read, feed it to the protocol machinery. This will
         * consume the read buffer upto the last full PDU, leaving behind a 
         * partial PDU if any bytes should remain
         */
        pread = bmp_protocol_read(server,client,client->rdbuf,client->rdptr);

        /*
         * If the protocol parsing detects an error, it will return NULL
         */
        if (pread == NULL) return rc;
 
        /*
         * Protocol should *not* read past the end of the read buffer
         */
        assert(pread <= client->rdptr);

        /*
         * Copy the fragment PDU to the head of the read buffer. The protocol
         * read always happens from the head of the read buffer
         */
        memcpy(client->rdbuf, pread, client->rdptr - pread);
        client->rdptr = client->rdbuf + (client->rdptr - pread);
    }
    
    }

    return rc;

bmp_client_close:

    bmp_close_client(server, client, 0);
    return rc;  

bmp_read_error:

    bmp_close_client(server, client, 1);
    return rc;         
}


int
bmp_process_client(bmp_server *server, int fd, int events)
{
    int rc = 0;
    bmp_client *client;

    client = server->clients[fd];

    assert(client != NULL);
    assert(client->fd == fd);

    rc = bmp_net_read(server, client);

    return rc;
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
 * Create a bmp_client entry in the server->clients list
 * Queue the accepted fd to the same epoll queue as the server socket
 */
static int
bmp_create_client(bmp_server *server, int fd)
{
    int rc;
    struct epoll_event ev;
    bmp_client *client;

    rc = bmp_so_nonblock(fd);
 
    if (rc < 0) {
        return rc;
    }


    if (fd > BMP_CLIENT_MAX - 1) {
        
    }

    /*
     * Use the fd as an index into the server->clients array and initialize
     * the client slot
     */
    client = calloc(1, sizeof(bmp_client));

    if (client == NULL) {
        return -1;
    } 

    client->fd = fd;
    assert(server->clients[fd] == NULL);
    server->clients[fd] = client;
    client->rdptr = client->rdbuf;
    
    bmp_log("BMP-ADJCHANGE: %d UP", fd);
   
    /*
     * Queue the client fd into the server's epoll queue
     */
    ev.data.fd = fd;
    ev.events = EPOLLIN | EPOLLET;
    rc = epoll_ctl(server->eq, EPOLL_CTL_ADD, fd, &ev);  
 
    if (rc < 0) {
        fprintf(stdout, "epoll_ctl(+fd) failed: %s\n", strerror(errno));
    }

    return rc;
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

        rc = bmp_create_client(server, fd);
    }
  
    return rc;
}


void
bmp_process_command(bmp_server *server, char *cmd, int len)
{


}


void
bmp_console_prompt()
{
    printf("BMP# ");
    fflush(stdout);
}


void
bmp_process_console(bmp_server *server, int events)
{
    char cmd[BMP_CMD_MAX];
    int rc;

    rc = read(STDIN_FILENO, cmd, BMP_CMD_MAX);
    
    if (rc > BMP_CMD_MAX - 1) {
        // input command is too long
    }

    cmd[rc] = 0;
    bmp_process_command(server, cmd, rc);
    

    bmp_console_prompt();
}


void
bmp_process_console2(bmp_server *server, int events)
{
    int rc;
    char c[16], ch;
    rc = read(0, c, 16);
    ch = c[0];
    c[rc] = 0;
  
    if (ch == 13) {

        printf("\r\n");
        bmp_console_prompt();

    } else if (ch == 127) {

        printf("\b \b");
        fflush(stdout);

    } else {

        printf("%d.%d ", ch, rc);
        fflush(stdout);

    }
}


int
bmp_console_init(bmp_server *server)
{
    int rc = 0;
    struct epoll_event ev;

#if 0
    struct termios tio;
    tio.c_lflag &=(~ICANON & ~ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &tio);
#endif


    ev.data.fd = STDIN_FILENO;
    ev.events = EPOLLIN | EPOLLET;
   
    rc = epoll_ctl(server->eq, EPOLL_CTL_ADD, STDIN_FILENO, &ev);

    if (rc < 0) {
        fprintf(stdout, "epoll_ctl(stdin) failed: %s\n", strerror(errno));
        return rc;
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
 
    rc = listen(server->fd, BMP_CLIENT_MAX);

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

    server->ev = calloc(BMP_CLIENT_MAX, sizeof(ev));

    if (server->ev == NULL) {
        fprintf(stdout, "calloc(EPOLL_MAX) failed\n");
        return -1;
    }

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

                bmp_process_console(server, e);

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

    bmp_server_init(&server, 1111);
    bmp_console_init(&server);
    bmp_server_run(&server);

    return 0;
}
            


            


