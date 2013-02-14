#ifndef __BMP_PEER_H__
#define __BMP_PEER_H__

#include "avl.h"
#include "bmp_client.h"
#include "bmp_protocol.h"

#define BMP_PEER_HDR_COMP_LEN 32

typedef struct bmp_peer_ {
    avl_node  avl;
    char      name[256];
 
    uint8_t   type;
    uint8_t   flags;
    uint8_t   rd[8];
    uint8_t   addr[16];
    uint32_t  asn;
    uint32_t  id;

    bmp_peer_hdr      *hdr;
    bmp_peer_up_msg   *up;
    bmp_peer_down_msg *down;

    bmp_client *client;
} bmp_peer;
 

int bmp_peer_compare(void *a, void *b, void *c);


#endif


