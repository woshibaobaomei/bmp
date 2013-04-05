#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "bmp_log.h"
#include "bmp_recv.h"
#include "bgp_router.h"
#include "bmp_session.h"
#include "bmp_process.h"


int
bmp_session_compare(void *a, void *b, void *c)
{
    bmp_session *A = (bmp_session*)a;
    bmp_session *B = (bmp_session*)b;

    return (A->fd - B->fd);
}


static void
bmp_session_cleanup(bmp_session *session)
{
    //free(client);
}


int
bmp_session_close(bmp_session *session, int reason)
{
    assert(session != NULL);
    assert(session->fd != 0);

    avl_remove(session->server->sessions, session, NULL);

    bmp_log("BMP-ADJCHANGE: Router %s:%d DOWN (%s)", session->router->name, session->port,
             BMP_SESSION_CLOSE_REASON(reason));


    close(session->fd); // this will also remove the fd from the epoll queue

    bmp_session_cleanup(session);

    return 0;
}


int
bmp_protocol_error(bmp_session *session, int error) 
{
    /*
     * TODO: do some book-keeping here
     */

    bmp_session_close(session, BMP_SESSION_PROTOCOL_ERROR);

    return 0;
}


/* 
 * Create a bmp_session entry in the server->session avl tree
 * Queue the accepted fd to the same epoll queue as the server socket
 */
int
bmp_session_create(bmp_server *server, int fd, struct sockaddr *addr, socklen_t slen)
{
    int rc;
    struct epoll_event ev;
    bmp_session *session;
    bgp_router *router;

    rc = fd_nonblock(fd);
 
    if (rc < 0) {
        return rc;
    }

    if (fd > BMP_SESSION_MAX - 1) {
        bmp_log("new session dropped. fd '%d' > BMP_SESSION_MAX", fd);
        close(fd);
        return -1;
    }

    session = calloc(1, sizeof(bmp_session));

    if (session == NULL) {
        return -1;
    } 

    session->server = server;
    session->fd = fd;
    session->rdbuf = calloc(1, BMP_RDBUF_MAX);
    session->rdptr = session->rdbuf;

    if (session->rdptr == NULL) {
        bmp_log("session rdbuffer alloc failed");
        free(session);
        return -1;
    }

    memcpy(&session->addr, addr, slen);
    session->port = bmp_sockaddr_port(&session->addr);
    gettimeofday(&session->time, NULL);

    avl_insert(server->sessions, session, NULL); 

    /*
     * Queue the client fd into the server's epoll queue
     */
    ev.data.fd = fd;
    ev.events = EPOLLIN | EPOLLET;
    rc = epoll_ctl(server->eq, EPOLL_CTL_ADD, fd, &ev);  
 
    if (rc < 0) {
        bmp_log("epoll_ctl(EPOLL_CTL_ADD, %d) failed: %s", fd, strerror(errno));
        bmp_session_close(session, BMP_SESSION_LISTEN_ERROR);
    }

    router = bgp_router_add(session, &session->addr, 0);

    bmp_log("BMP-ADJCHANGE: Router %s:%d UP", router->name, session->port);

    return rc;
}


static int
bmp_session_read(bmp_session *session)
{
    int rc = 1, error = 0, space;
    uint64_t msgs;
    char *pread;

    assert(session->fd != 0);
    assert(session->router != NULL);

    msgs = session->router->msgs;

    while (rc > 0) {

    while ((space = BMP_RDBUF_SPACE(session)) > 0) {

        rc = read(session->fd, session->rdptr, space);

        if (rc <= 0) {
            error = errno;
            break;
        }

        session->server->bytes += rc; 
        session->bytes += rc;           
        session->rdptr += rc;
    }    

    if (session->rdptr - session->rdbuf > 0) {
        /*
         * Whatever we read, feed it to the protocol machinery. This will
         * consume the read buffer upto the last full PDU, leaving behind a 
         * partial PDU if any bytes should remain
         */
        pread = bmp_recv(session, session->rdbuf, session->rdptr);
        
        /*
         * If the protocol parsing detects an error, it will return NULL
         */
        if (pread == NULL) return rc;
 
        /*
         * Protocol should *not* read past the end of the read buffer
         */
        assert(pread <= session->rdptr);

        /* 
         * If pread == client->rdbuf for too many iterations, we have an issue
         */
        
        /*
         * Copy the fragment PDU to the head of the read buffer. The protocol
         * read always happens from the head of the read buffer
         */
        if (pread < session->rdptr && pread != session->rdbuf) {
            memcpy(session->rdbuf, pread, session->rdptr - pread);
        }
        
        session->rdptr = session->rdbuf + (session->rdptr - pread);
    }
    
    }

    /*
     * If we read at least one full PDU from this session we have to signal the 
     * processing task to "process" this session now.  Note: at this point, the 
     * session COULD be in inactive state (session torn down, etc)
     */
    if (session->router->msgs - msgs) {
        bmp_process_signal(session->router);
    }

    if (rc == 0) {
        bmp_session_close(session, BMP_SESSION_REMOTE_CLOSE); 
    }
    
    if (rc < 0 && error != EAGAIN) {
        bmp_session_close(session, BMP_SESSION_READ_ERROR);
    }
    
    return rc;         
}


int
bmp_session_process(bmp_server *server, int fd, int events)
{
    int rc = 0;
    bmp_session *session, search;

    search.fd = fd;
    session = (bmp_session*)avl_lookup(server->sessions, &search, NULL);

    assert(session != NULL);
    assert(session->router != NULL);

    rc = bmp_session_read(session);

    return rc;
}

