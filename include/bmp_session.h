#ifndef __BMP_SESSION_H__
#define __BMP_SESSION_H__

#include <sys/time.h>
#include "bmp_util.h"
#include "bmp_server.h"


#define BMP_SESSION_MAX (1 << 12)
   
/*
 * 
 */
#define BMP_SESSION_REMOTE_CLOSE   0
#define BMP_SESSION_READ_ERROR     1
#define BMP_SESSION_LISTEN_ERROR   2
#define BMP_SESSION_PROTOCOL_ERROR 3

#define BMP_SESSION_CLOSE_REASON(cr) ( \
  cr == BMP_SESSION_REMOTE_CLOSE   ? "remote closed"  : \
  cr == BMP_SESSION_READ_ERROR     ? "read error"     : \
  cr == BMP_SESSION_LISTEN_ERROR   ? "listen error"   : \
  cr == BMP_SESSION_PROTOCOL_ERROR ? "protocol error" : \
                                     "unknown")

#define BMP_RDBUF_MAX      (1 << 16) 
#define BMP_RDBUF_SPACE(c) ((c)->rdbuf+BMP_RDBUF_MAX-(c)->rdptr)

/*
 *
 */
typedef struct bgp_router_  bgp_router;
typedef struct bmp_session_ bmp_session;

struct bmp_session_ {
    avl_node       avl;
    int            fd;
    char          *rdptr;
    char          *rdbuf;
    struct timeval time;
    bmp_sockaddr   addr;
    uint16_t       port;
    uint64_t       bytes;
    bgp_router    *router;
    bmp_server    *server;
};

int bmp_session_create(bmp_server *server, int fd, struct sockaddr *addr, socklen_t slen);
int bmp_session_process(bmp_server* server, int fd, int events);
int bmp_session_close(bmp_session *session, int reason);
int bmp_protocol_error(bmp_session *session, int reason);
int bmp_session_compare(void *a, void *b, void *c);


#endif
