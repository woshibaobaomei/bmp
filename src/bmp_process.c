#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include "bmp_log.h"
#include "bmp_util.h"
#include "bgp_peer.h"
#include "bmp_timer.h"
#include "bgp_router.h"
#include "bmp_server.h"
#include "bmp_process.h"

/*
 * This thread wakes up every 2 seconds. When it does, it locks the process 
 * mutex and checks to see if there is any work to be done. If not, it releases 
 * the mutex and goes back to sleep (waits for the next timer event). If there 
 * IS work to be done (ie. there are routers in the queue) then it makes a copy 
 * of the router list while holding the process mutex. Once the copy is done, 
 * it releases the mutex and starts processing the clients in the copied list 
 */
static int             bmp_process_eq;
static epv            *bmp_process_ev;
static int             bmp_process_timer;
static pthread_t       bmp_process_thread;
static pthread_mutex_t bmp_process_mutex;
static bgp_router     *bmp_router_queue[BMP_SESSION_MAX];  // shared queue
static bgp_router     *bmp_process_queue[BMP_SESSION_MAX]; // copied queue
static int             bmp_router_qsize = 0;

/*
 * Max size of the process event queue
 */
#define BMP_PROCESS_BACKLOG 1024 



bgp_peer *
bmp_process_peer_hdr(bgp_router *router, char *data, int len)
{
    bgp_peer *peer, search;
    bmp_peer_hdr *peer_hdr = (bmp_peer_hdr *)data;
    search.hdr = peer_hdr;

    peer = (bgp_peer *)avl_lookup(router->peers, &search, NULL);

    if (peer != NULL) return peer;

    peer = bgp_peer_create(router, peer_hdr);

    return peer;
}

/*
 * Main routine that walks over the clients with pending BMP messages and 
 * processes new messages. It's up to the implementation here to define how to 
 * process the messages: database, in-memory store, etc. 
 */
static int 
bmp_process()
{
    int rc = 0, index, routers = 0;
    bgp_router *router;
 
    routers = bmp_process_consume();

    for (index = 0; index < routers; index++) {
        router = bmp_process_queue[index];
        if (router == NULL) continue;
   
    }

    return rc;
}


// BMP processing infra -------------------------------------------------------


int 
bmp_process_signal(bgp_router *router)
{
    pthread_mutex_lock(&bmp_process_mutex);
    bmp_router_queue[bmp_router_qsize++] = router;
    pthread_mutex_unlock(&bmp_process_mutex);
    return 0;
}


int
bmp_process_consume()
{
    int rc = 0;

    BMP_TIMER_READ(bmp_process_timer, rc);

    /*
     * Copy out the clients list into a separate memory space and work on that
     */
    pthread_mutex_lock(&bmp_process_mutex);
    rc = bmp_router_qsize;
    memcpy(bmp_process_queue, bmp_router_queue, rc * sizeof(bgp_router*));
    bmp_router_qsize = 0;
    pthread_mutex_unlock(&bmp_process_mutex);

    return rc;
}


static void *
bmp_process_loop(void *arg)
{
    int i, ev, n, fd;

    while (1) {

        n = epoll_wait(bmp_process_eq, bmp_process_ev, BMP_PROCESS_BACKLOG, -1);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                bmp_log("epoll_wait error: %s", strerror(errno));
                return NULL;
            }
        }

        for (i = 0; i < n; i++) {
            ev = bmp_process_ev[i].events; 
            fd = bmp_process_ev[i].data.fd;
            if ((ev & EPOLLERR) || (ev & EPOLLHUP)) continue;
            if (fd == bmp_process_timer) bmp_process();
        }
    }

    return NULL;
}


int 
bmp_process_run() 
{
    int rc;

    rc = pthread_create(&bmp_process_thread, NULL, bmp_process_loop, NULL);

    if (rc < 0) {
        bmp_log("bmp_process_thread create failed: %s", strerror(errno));
        return -1;
    }

    return 0;
}


int 
bmp_process_init() 
{
    int rc;
    struct epoll_event ev;

    /*
     * Create the epoll instance and register the listen socket with the server 
     * epoll queue 
     */
    bmp_process_eq = epoll_create(BMP_PROCESS_BACKLOG);

    if (bmp_process_eq < 0) {
        bmp_log("epoll_create1() failed: %s", strerror(errno));
        return -1;
    }

    /*
     * Create a timer fd and register the read-end of the timer pipe with the 
     * process epoll queue
     */
    bmp_process_timer = bmp_timer_init();

    if (bmp_process_timer < 0) {
        bmp_log("process timer init failed");
        return -1;
    }

    ev.data.fd = bmp_process_timer;
    ev.events = EPOLLIN | EPOLLET;

    rc = epoll_ctl(bmp_process_eq, EPOLL_CTL_ADD, bmp_process_timer, &ev);
 
    if (rc < 0) {
        bmp_log("process timer listen error: %s", strerror(errno));
        return rc;
    }

    /*
     * Allocate the process event queue
     */
    bmp_process_ev = calloc(BMP_PROCESS_BACKLOG, sizeof(ev));

    if (bmp_process_ev == NULL) {
        bmp_log("calloc(bmp_process_ev) failed");
        return -1;
    }

    return 0;
}
