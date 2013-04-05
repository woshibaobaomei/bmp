#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include "avl.h"
#include "bgp_peer.h"
#include "bgp_router.h"
#include "bmp_command.h"
#include "bmp_protocol.h"


/*
 * Compare two bmp_peer structs for avl lookup. This needs to be optimized 
 * since there is a lookup for every client message that has a peer header  
 */
int 
bgp_peer_compare(void *a, void *b, void *c)
{
    int t = 0, v = 0;
    bgp_peer *A = (bgp_peer *)a;
    bgp_peer *B = (bgp_peer *)b;

    bmp_peer_hdr *h1 = A->hdr;
    bmp_peer_hdr *h2 = B->hdr;

    if ((t = h1->type) != h2->type) {

    }
    
    

    if ((v = (h1->flags & 0x01)) != (h2->flags & 0x01)) {

    }

    // if t is 0 (global peer) no need to compare RDs
    // if v is 0 (IPv6 peer) no need to do 16 byte memcmp
    if (t == 0) {

    }

    return memcmp(h1->addr+(v?0:12), h2->addr+(v?0:12), (v?16:4));
}


bgp_peer *
bgp_peer_create(bgp_router *router, bmp_peer_hdr *hdr)
{    
    char rd[64];
    char addr[128];
    avl_node *insert = NULL;
    bgp_peer *peer = calloc(1, sizeof(bgp_peer));

    if (peer == NULL) {
        // TODO: nomem
    }

    peer->hdr = calloc(1, BMP_PEER_HDR_COMP_LEN);

    if (peer->hdr == NULL) {
        // TODO: nomem
    }

    memcpy(peer->hdr, hdr, BMP_PEER_HDR_COMP_LEN);

    bmp_ipaddr_string((peer->hdr->flags & BMP_PEER_FLAG_V ? 
                       peer->hdr->addr : peer->hdr->addr + 0xC), 
                      (peer->hdr->flags & BMP_PEER_FLAG_V ? 
                       AF_INET6 : AF_INET), addr, sizeof(addr));

    snprintf(peer->name, sizeof(peer->name), "%s", addr);

    //bmp_log("create: %s", addr);

    insert = avl_insert(router->peers, (void*)peer, NULL);

    assert(insert != NULL);

    return peer;
}

 

// bgp peer show commands -----------------------------------------------------


static int
bmp_show_bgp_router_peers_walker(void *node, void *ctx)
{
    int id = ++(*((int*)ctx));

    //char name[32];
    char up[32];
    char rd[32];
    char asn[32];
    char addr[32];
    char bgpid[32];

    bgp_peer *peer = node;
    uptime_string((uint32_t)now.tv_sec - ntohl(*(uint32_t *)peer->hdr->tv_sec), up, sizeof(up));
    snprintf(rd, sizeof(rd), "%d", (int)peer->hdr->rd[7]);
    snprintf(asn, sizeof(asn), "%"PRIu32, ntohl(*(uint32_t *)peer->hdr->asn));
    if (!(peer->hdr->flags & 0x80)) {
        snprintf(addr, sizeof(addr), "%u%s%u%s%u%s%u",
                             peer->hdr->addr[12], ".",
                             peer->hdr->addr[13], ".",
                             peer->hdr->addr[14], ".",
                             peer->hdr->addr[15]);
    } else {
	//TODO: Print IPv6 in shortened version
    }
    snprintf(bgpid, sizeof(bgpid), "%"PRIu8"%s%"PRIu8"%s%"PRIu8"%s%"PRIu8,
                                 *(uint8_t *)peer->hdr->id, ".",
                                 peer->hdr->id[1], ".",
                                 peer->hdr->id[2], ".",
                                 peer->hdr->id[3]);

    if (id == 1)
    dprintf(out, " ID    Name                Uptime         R-D       AS-Number  BGP-ID \n");
    dprintf(out, "%3d    %-20s"              "%-15s"        "%-10s"   "%-11s"    "%s\n",
            id,
            addr,
            up,
            rd,
            asn,
	    bgpid);

    return AVL_SUCCESS;
}


int
bmp_show_bgp_router_peers(bgp_router *router)
{

    int id = 0;

    if (avl_size(router->peers) == 0) {
        dprintf(out, "%% No peers\n");
        return 0;
    }

    dprintf(out, "\n");
    avl_walk(router->peers,
             bmp_show_bgp_router_peers_walker,
             &id,
             AVL_WALK_INORDER);
    dprintf(out, "\n");

    return 0;
}


int
bmp_show_bgp_router_peer_command(bgp_router *router, char *cmd)
{

    return 0;
}

