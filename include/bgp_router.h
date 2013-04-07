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
    bmp_lock_t    peers_lock;
    bgp_router   *prev;
    bgp_router   *next;
    bmp_session  *session;
    bmp_sesslog  *slog;
};


/*
 * BGP router flags: 
 *  
 * ACTIVE - the TCP session with the router is currently up 
 *  
 * MULTIPORT - multiple sessions from a single IP but different ports. We can't 
 * persist the data for these types of sessions (once session goes down, it has 
 * to be cleaned up. Used mostly for testing
 *  
 */
#define BGP_ROUTER_ACTIVE    0x00000001
#define BGP_ROUTER_MULTIPORT 0x00000002


int 
bgp_router_compare(void *a, void *b, void *c);


bgp_router *
bgp_router_session_add(bmp_session *session);


void
bgp_router_session_remove(bmp_session *session);


int
bmp_show_bgp_routers();

int 
bmp_show_bgp_router_command(char *cmd);

#endif

