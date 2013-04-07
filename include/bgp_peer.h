#ifndef __BGP_PEER_H__
#define __BGP_PEER_H__

#include "avl.h"
#include "bgp_router.h"
#include "bmp_session.h"
#include "bmp_protocol.h"

#define BMP_PEER_HDR_COMP_LEN 42

typedef struct bgp_peer_ {
    avl_node      avl;
    char          name[256];
    bmp_peer_hdr *hdr;
    bgp_router   *router;
    
} bgp_peer;
 

int 
bgp_peer_compare(void *a, void *b, void *c);


bgp_peer *
bgp_peer_create(bgp_router *router, bmp_peer_hdr *hdr);


int
bmp_show_bgp_router_peers(bgp_router *router);

int
bmp_show_bgp_router_peer_command(bgp_router *router, char *cmd);


#endif


