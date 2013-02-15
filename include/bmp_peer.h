#ifndef __BMP_PEER_H__
#define __BMP_PEER_H__

#include "avl.h"
#include "bmp_client.h"
#include "bmp_protocol.h"

#define BMP_PEER_HDR_COMP_LEN 34

typedef struct bmp_peer_ {
    avl_node  avl;
    char      name[256];

    bmp_peer_hdr      *hdr;
    bmp_peer_up_msg   *up;
    bmp_peer_down_msg *down;

    bmp_client *client;
} bmp_peer;
 

int bmp_peer_compare(void *a, void *b, void *c);
bmp_peer *bmp_peer_create(bmp_client *client, bmp_peer_hdr *hdr);


#endif


