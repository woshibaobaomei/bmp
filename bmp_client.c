#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "bmp_util.h"
#include "bmp_client.h"
#include "bmp_server.h"
#include "bmp_protocol.h"


static void
bmp_client_cleanup(bmp_client *client)
{
    free(client);
}


int
bmp_client_close(bmp_server *server, bmp_client *client, int reason)
{
    assert(client != NULL);
    assert(client->fd != 0);

    server->client[client->fd] = NULL;
    server->clients--;

    bmp_log("BMP-ADJCHANGE: %d Down (%s)", client->fd,
             BMP_CLIENT_CLOSE_REASON(reason));


    close(client->fd); // this will also remove the fd from the epoll queue

    bmp_client_cleanup(client);

    return 0;
}


static int
bmp_client_read(bmp_server *server, bmp_client *client)
{
    int rc = 1, space;
    char *pread;

    assert(client->fd != 0);

    while (rc > 0) {

    while ((space = BMP_RDBUF_SPACE(client)) > 0) {

        rc = read(client->fd, client->rdptr, space);

        if (rc > 0) {
            
            server->bytes += rc; 
            client->bytes += rc;           
            client->rdptr += rc;
         
        } else if (rc == 0) {

            goto remote_close;
 
        } else {

            if (errno != EAGAIN) goto read_error;
            
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
        if (pread < client->rdptr) {
            memcpy(client->rdbuf, pread, client->rdptr - pread);
        }
        
        client->rdptr = client->rdbuf + (client->rdptr - pread);
    }
    
    }

    return rc;

remote_close:

    bmp_client_close(server, client, BMP_CLIENT_REMOTE_CLOSE);
    return rc;  

read_error:

    bmp_client_close(server, client, BMP_CLIENT_READ_ERROR);
    return rc;         
}


int
bmp_client_process(bmp_server *server, int fd, int events)
{
    int rc = 0;
    bmp_client *client;

    client = server->client[fd];

    assert(client != NULL);
    assert(client->fd == fd);

    rc = bmp_client_read(server, client);

    return rc;
}


/* 
 * Create a bmp_client entry in the server->client list
 * Queue the accepted fd to the same epoll queue as the server socket
 */
int
bmp_client_create(bmp_server *server, int fd)
{
    int rc;
    struct epoll_event ev;
    bmp_client *client;

    rc = fd_nonblock(fd);
 
    if (rc < 0) {
        return rc;
    }

    if (fd > BMP_CLIENT_MAX - 1) {
        bmp_log("new client dropped. fd '%d' > BMP_CLIENT_MAX", fd);
        close(fd);
        return -1;
    }

    /*
     * Use the fd as an index into the server->client array and initialize
     * the client slot
     */
    client = calloc(1, sizeof(bmp_client));

    if (client == NULL) {
        return -1;
    } 

    client->fd = fd;
    assert(server->client[fd] == NULL);
    server->client[fd] = client;
    client->rdptr = client->rdbuf;
    server->clients++;   
 
    bmp_log("BMP-ADJCHANGE: %d UP", fd);
   
    /*
     * Queue the client fd into the server's epoll queue
     */
    ev.data.fd = fd;
    ev.events = EPOLLIN | EPOLLET;
    rc = epoll_ctl(server->eq, EPOLL_CTL_ADD, fd, &ev);  
 
    if (rc < 0) {
        bmp_log("epoll_ctl(EPOLL_CTL_ADD, %d) failed: %s", fd, strerror(errno));
        bmp_client_close(server, client, BMP_CLIENT_LISTEN_ERROR);
    }

    return rc;
}

