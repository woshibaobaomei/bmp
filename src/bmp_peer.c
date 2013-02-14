#include <stdlib.h>
#include <string.h>
#include "bmp_peer.h"
#include "bmp_client.h"


int bmp_peer_compare(void *a, void *b, void *c)
{
    bmp_peer *A = (bmp_peer *)a;
    bmp_peer *B = (bmp_peer *)b;

    return memcmp(&A->hdr->rd, &B->hdr->rd, BMP_PEER_HDR_COMP_LEN);
}

 
