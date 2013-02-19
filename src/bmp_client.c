#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <sys/time.h>

#include "bmp_util.h"
#include "bmp_peer.h"
#include "bmp_client.h"
#include "bmp_server.h"
#include "bmp_protocol.h"


int
bmp_client_fd_compare(void *a, void *b, void *c)
{
    bmp_client *A = (bmp_client*)a;
    bmp_client *B = (bmp_client*)b;

    return (A->fd - B->fd);
}

int
bmp_client_addr_compare(void *a, void *b, void *c)
{
    bmp_client *A = (bmp_client*)a;
    bmp_client *B = (bmp_client*)b;

    return bmp_sockaddr_compare(&A->addr, &B->addr, 1);
}


static void
bmp_client_cleanup(bmp_client *client)
{
    free(client);
}


int
bmp_client_close(bmp_client *client, int reason)
{
    assert(client != NULL);
    assert(client->fd != 0);

    avl_multi_remove(client->server->clients, client, NULL);

    bmp_log("BMP-ADJCHANGE: %s:%d Down (%s)", client->name, client->port,
             BMP_CLIENT_CLOSE_REASON(reason));


    close(client->fd); // this will also remove the fd from the epoll queue

    bmp_client_cleanup(client);

    return 0;
}


static int
bmp_client_read(bmp_client *client)
{
    int rc = 1, error = 0, space;
    char *pread;

    assert(client->fd != 0);

    while (rc > 0) {

    while ((space = BMP_RDBUF_SPACE(client)) > 0) {

        rc = read(client->fd, client->rdptr, space);

        if (rc <= 0) {
            error = errno;
            break;
        }
            
        client->server->bytes += rc; 
        client->bytes += rc;           
        client->rdptr += rc;
    }    

    if (client->rdptr - client->rdbuf > 0) {
        /*
         * Whatever we read, feed it to the protocol machinery. This will
         * consume the read buffer upto the last full PDU, leaving behind a 
         * partial PDU if any bytes should remain
         */
        pread = bmp_protocol_read(client, client->rdbuf, client->rdptr);
        
        /*
         * If the protocol parsing detects an error, it will return NULL
         */
        if (pread == NULL) return rc;
 
        /*
         * Protocol should *not* read past the end of the read buffer
         */
        assert(pread <= client->rdptr);

        /* 
         * If pread == client->rdbuf for too many iterations, we have an issue
         */
        
        /*
         * Copy the fragment PDU to the head of the read buffer. The protocol
         * read always happens from the head of the read buffer
         */
        if (pread < client->rdptr && pread != client->rdbuf) {
            memcpy(client->rdbuf, pread, client->rdptr - pread);
        }
        
        client->rdptr = client->rdbuf + (client->rdptr - pread);
    }
    
    }

    if (rc == 0) {
        bmp_client_close(client, BMP_CLIENT_REMOTE_CLOSE); 
    }
    
    if (rc < 0 && error != EAGAIN) {
        bmp_client_close(client, BMP_CLIENT_READ_ERROR);
    }
    
    return rc;         
}


int
bmp_client_process(bmp_server *server, int fd, int events)
{
    int rc = 0;
    bmp_client *client, search;

    search.fd = fd;
    client = (bmp_client*)avl_lookup(server->clients, &search, NULL);

    assert(client != NULL);

    rc = bmp_client_read(client);

    return rc;
}


/* 
 * Create a bmp_client entry in the server->client avl tree
 * Queue the accepted fd to the same epoll queue as the server socket
 */
int
bmp_client_create(bmp_server *server, int fd, struct sockaddr *addr, socklen_t slen)
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

    client = calloc(1, sizeof(bmp_client));

    if (client == NULL) {
        return -1;
    } 

    client->server = server;
    client->fd = fd;
    client->rdptr = client->rdbuf;
    client->peers = avl_init(bmp_peer_compare, NULL, AVL_TREE_INTRUSIVE);

    if (client->peers == NULL) {
        return -1;
    }

    memcpy(&client->addr, addr, slen);
    client->port = bmp_sockaddr_string(&client->addr, client->name, 128);
    gettimeofday(&client->time, NULL);

    avl_multi_insert(server->clients, client, NULL); 
 
    bmp_log("BMP-ADJCHANGE: %s:%d UP", client->name, client->port);
   
    /*
     * Queue the client fd into the server's epoll queue
     */
    ev.data.fd = fd;
    ev.events = EPOLLIN | EPOLLET;
    rc = epoll_ctl(server->eq, EPOLL_CTL_ADD, fd, &ev);  
 
    if (rc < 0) {
        bmp_log("epoll_ctl(EPOLL_CTL_ADD, %d) failed: %s", fd, strerror(errno));
        bmp_client_close(client, BMP_CLIENT_LISTEN_ERROR);
    }

    return rc;
}

