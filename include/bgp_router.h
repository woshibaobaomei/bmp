#ifndef __BGP_ROUTER_H__
#define __BMP_ROUTER_H__

#include <stdint.h>
#include <sys/time.h>
#include "avl.h"
#include "msg_chunk.h"
#include "bmp_util.h"
#include "bmp_protocol.h"
 
 
#define BGP_ROUTER_MAX     (1 << 12)
#define RTR_RDBUF_MAX      (1 << 16) 
#define RTR_RDBUF_SPACE(c) ((c)->rdbuf+RTR_RDBUF_MAX-(c)->rdptr)
 
struct bmp_server_;

typedef struct bgp_router_  bgp_router;

enum {
    BMP_SESSION_FD = 0,
    BGP_ROUTER_ADDR,
    BGP_ROUTER_AVL
};


/*
 * The bmp_client type represents a BGP speaker that has connected to us and 
 * is sending us data it receives (BGP updates) from its connected peers.  
 */
struct bmp_client_ {
    avl_node  avl[BMP_CLIENT_AVL];
    int       fd;
    char     *rdptr;
    char      rdbuf[BMP_RDBUF_MAX];
    char      name[128];

    /*
     *
     */
    bmp_sockaddr        addr;
    uint16_t            port;
    struct timeval      time;
    uint32_t            flags;
    uint64_t            bytes;
    uint64_t            msgs;    
    uint64_t            mstat[BMP_MESSAGE_TYPE_MAX]; 
    msg_head            mhead;
    avl_tree           *peers;
    struct bmp_server_ *server;
};


/*
 * Structure used during a search of the client tree
 */
typedef struct bmp_client_search_index_ {
    int id;
    int index;
    bmp_client *client;
    struct bmp_client_search_index_ *next;
} bmp_client_search_index;

 
struct bmp_message_ {
    struct timeval time;
    bmp_message   *next;
    bmp_message   *peer_next;
    unsigned char  data[0];
};


#define BMP_CLIENT_REMOTE_CLOSE   0
#define BMP_CLIENT_READ_ERROR     1
#define BMP_CLIENT_LISTEN_ERROR   2
#define BMP_CLIENT_PROTOCOL_ERROR 3

#define BMP_CLIENT_CLOSE_REASON(cr) ( \
  cr == BMP_CLIENT_REMOTE_CLOSE   ? "remote closed"  : \
  cr == BMP_CLIENT_READ_ERROR     ? "read error"     : \
  cr == BMP_CLIENT_LISTEN_ERROR   ? "listen error"   : \
  cr == BMP_CLIENT_PROTOCOL_ERROR ? "protocol error" : \
                                    "unknown")


int bmp_client_create(struct bmp_server_ *server, int fd, struct sockaddr *addr, socklen_t slen);
int bmp_client_process(struct bmp_server_* server, int fd, int events);
int bmp_client_close(bmp_client *client, int reason);
int bmp_client_fd_compare(void *a, void *b, void *c);
int bmp_client_addr_compare(void *a, void *b, void *c);


bmp_client *
bmp_find_client_token(struct bmp_server_ *server, char *token, 
                      bmp_client_search_index *idx);

#endif

