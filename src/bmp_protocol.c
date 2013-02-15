#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "bmp_peer.h"
#include "bmp_client.h"
#include "bmp_server.h"
#include "bmp_protocol.h"


static void
bmp_protocol_error(bmp_client *client, int error) 
{
    /*
     * TODO: do some book-keeping here
     */

    bmp_client_close(client, BMP_CLIENT_PROTOCOL_ERROR);
}


static bmp_peer *
bmp_recv_peer_hdr(bmp_client *client, char *data, int len)
{
    bmp_peer *peer, search;
    bmp_peer_hdr *peer_hdr = (bmp_peer_hdr *)data;
    search.hdr = peer_hdr;

    peer = (bmp_peer *)avl_lookup(client->peers, &search, NULL);

    if (peer != NULL) return peer;

    peer = bmp_peer_create(client, peer_hdr);

    return peer;
}


static int 
bmp_recv_route_monitoring(bmp_client *client, char *data, int len)
{
    bmp_peer *peer = bmp_recv_peer_hdr(client, data, len);

    if (peer == NULL) {
        
    }

    return len;
}


static int 
bmp_recv_statistics_report(bmp_client *client, char *data, int len)
{
    bmp_peer *peer = bmp_recv_peer_hdr(client, data, len);

    if (peer == NULL) {
        
    }
    return len;
}


static int
bmp_recv_peer_up_notification(bmp_client *client, char *data, int len)
{
    bmp_peer *peer = bmp_recv_peer_hdr(client, data, len);

    if (peer == NULL) {

    }


    return len;
}


static int 
bmp_recv_peer_down_notification(bmp_client *client, char *data, int len)
{
    bmp_peer *peer = bmp_recv_peer_hdr(client, data, len);

    if (peer == NULL) {

    }

    return len;
}


static int
bmp_recv_initiation_message(bmp_client *client, char *data, int len)
{

    return len;
}


static int
bmp_recv_termination_message(bmp_client *client, char *data, int len)
{

    return len;
}


static int
bmp_recv_msg_hdr(bmp_client *client, char *data, int *len)
{
    uint32_t vers, type, mlen;
    bmp_msg_hdr *hdr = (bmp_msg_hdr*)data;
 
    if (*len < BMP_MSG_HDR_LEN) {
        return BMP_MSG_HDR_WAIT;
    }

    vers = hdr->version;
    mlen = ntohl(hdr->length);
    type = hdr->type;

    if (mlen < BMP_MSG_HDR_LEN || mlen > BMP_MSG_MAX_LEN) {
        bmp_protocol_error(client, BMP_INVALID_MSG_LENGTH);
        return BMP_MSG_HDR_ERROR;
    }

    if (*len < mlen) {
        return BMP_MSG_HDR_WAIT;
    }

    if (vers != 3) {
        bmp_protocol_error(client, BMP_INVALID_MSG_VERSION);
        return BMP_MSG_HDR_ERROR;
    }

    *len = mlen;

    return (int)type;
}


static int
bmp_recv_msg(bmp_client *client, char *data, int len)
{
    int rc, hdr;
 
    hdr = bmp_recv_msg_hdr(client, data, &len);

    if (hdr < 0) {
        if (hdr == BMP_MSG_HDR_WAIT) return 0;
        if (hdr == BMP_MSG_HDR_ERROR) return -1;
        assert(0);
    }

    client->server->msgs++;
    client->msgs++;

    data += BMP_MSG_HDR_LEN;

    switch (hdr) {
    case BMP_ROUTE_MONITORING:
        rc = bmp_recv_route_monitoring(client, data, len);        
        break;
    case BMP_STATISTICS_REPORT:
        rc = bmp_recv_statistics_report(client, data, len);
        break;
    case BMP_PEER_UP_NOTIFICATION:
        rc = bmp_recv_peer_up_notification(client, data, len);
        break;
    case BMP_PEER_DOWN_NOTIFICATION:
        rc = bmp_recv_peer_down_notification(client, data, len);
        break;
    case BMP_INITIATION_MESSAGE:
        rc = bmp_recv_initiation_message(client, data, len);
        break;
    case BMP_TERMINATION_MESSAGE:
        rc = bmp_recv_termination_message(client, data, len);
        break;
    default:
        // TODO: warning about invalid message type
        rc = -1;
        break;
    }

    return rc;
}


char *
bmp_protocol_read(bmp_client *client, char *data, char *end)
{
    int rc = 1;

    while (rc > 0 && data < end) {

        rc = bmp_recv_msg(client, data, end-data);

        if (rc > 0) {
            data += rc;
        } else if (rc < 0) {
            return NULL;
        }
    }

    return data;   
}


