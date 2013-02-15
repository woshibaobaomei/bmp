#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "avl.h"
#include "bmp_peer.h"
#include "bmp_client.h"
#include "bmp_protocol.h"


/*
 * Compare two bmp_peer structs for avl lookup. This needs to be optimized 
 * since there is a lookup for every client message that has a peer header  
 */
int 
bmp_peer_compare(void *a, void *b, void *c)
{
    bmp_peer *A = (bmp_peer *)a;
    bmp_peer *B = (bmp_peer *)b;

    bmp_peer_hdr *h1 = A->hdr;
    bmp_peer_hdr *h2 = B->hdr;

    if (h1->type != h2->type) {
    
    }
    
    // if type is 0 (global peer) no need to compare RDs

    if ((h1->flags & BMP_PEER_FLAG_V) != (h2->flags & BMP_PEER_FLAG_V)) {

    }

    // if flags indicate IPv4 peer, no need to do 16 byte memcmp

    return memcmp(h1->addr+12, h2->addr+12, 4);
}


bmp_peer *
bmp_peer_create(bmp_client *client, bmp_peer_hdr *hdr)
{    
    char rd[64];
    char addr[128];
    avl_node *insert = NULL;
    bmp_peer *peer = calloc(1, sizeof(bmp_peer));

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


    insert = avl_insert(client->peers, (void*)peer, NULL);

    assert(insert != NULL);

    return peer;
}

 
