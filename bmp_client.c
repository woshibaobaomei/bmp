
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "bmp_client.h"
#include "bmp_server.h"
#include "bmp_protocol.h"


static void
bmp_cleanup_client(bmp_client *client)
{


}


int
bmp_close_client(bmp_server *server, bmp_client *client, int reason)
{
    assert(client != NULL);
    assert(client->fd != 0);

    server->clients[client->fd] = NULL;


    bmp_log("BMP-ADJCHANGE: %d DN (reason: %d)", client->fd, reason);


    close(client->fd); // this will also remove the fd from the epoll queue

    bmp_cleanup_client(client);

    return 0;
}


static int
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


/* 
 * Create a bmp_client entry in the server->clients list
 * Queue the accepted fd to the same epoll queue as the server socket
 */
int
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
        bmp_log("epoll_ctl(EPOLL_CTL_ADD, %d) failed: %s", fd, strerror(errno));
        bmp_close_client(server, client, 3);
    }

    return rc;
}

