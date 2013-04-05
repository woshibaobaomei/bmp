#ifndef __BGP_ROUTER_H__
#define __BGP_ROUTER_H__

#include <stdint.h>
#include <sys/time.h>
#include "avl.h"
#include "msg_chunk.h"
#include "bmp_util.h"
#include "bmp_session.h"
#include "bmp_protocol.h"

/*
 * The bgp_router type represents a BGP router that has connected to us and 
 * is sending us data it receives (BGP updates, etc) from its connected peers.
 *
 * bgp_router's are keyed in an AVL tree by their IP address. If there is more 
 * than one router with the same IP address (different ports from the same IP, 
 * for example, we store them in a chain hanging off the AVL tree node:
 *
 * The following diagram shows 8 router objects (identified by ip:port pairs), 
 * 3 belonging to the tree and the rest hanging off a tree node:
 *
 *   1.1.1.1:100 (tree node)
 *   2.2.2.2:200 (tree node)
 *   2.2.2.2:300
 *   2.2.2.2:400
 *   3.3.3.3:300 (tree node)
 *   3.3.3.3:400
 *   3.3.3.3:500
 *   3.3.3.3:600
 *
 *                    +-------------+
 *                    |             |
 *                    | 1.1.1.1:100 |
 *                    |             |
 *                    +-------------+  
 *                      /         \
 *                     /           \
 *                    /             \
 *        +-------------+         +-------------+
 *        |             |         |             |
 *        | 2.2.2.2:200 |         | 3.3.3.3:300 |
 *        |             |         |             | 
 *        +-------------+         +-------------+
 *               \                        \
 *                \  +-----+  +-----+      \  +-----+  +-----+  +-----+
 *                 `>| 300 |->| 400 |       `>| 400 |->| 500 |->| 600 |
 *                   +-----+  +-----+         +-----+  +-----+  +-----+
 *
 */
struct bgp_router_ {
    avl_node      avl;
    bmp_sockaddr  addr;
    uint16_t      port;
    char          name[128];
    uint32_t      flags;
    uint64_t      msgs;    
    uint64_t      mstat[BMP_MESSAGE_TYPE_MAX]; 
    msg_head      mhead;
    avl_tree     *peers;
    bgp_router   *prev;
    bgp_router   *next;
    bmp_session  *session;
};


/*
 * Structure used during a search of the router tree
 */
typedef struct bgp_router_search_index_ {
    int id;
    int port;
    int index;
    bgp_router *router;
    struct bgp_router_search_index *next;
} bgp_router_search_index;

 
#define BGP_ROUTER_CONTEXT_DEFAULT 0
#define BGP_ROUTER_CONTEXT_TEMP    1
#define BGP_ROUTER_CONTEXT_MAX     2


int
bgp_router_init();


avl_tree *
bgp_routers(int context);


bgp_router *
bgp_router_add(bmp_session *session, bmp_sockaddr *addr, int context);


int
bmp_show_bgp_routers();

int 
bmp_show_bgp_router_command(char *cmd);

#endif

