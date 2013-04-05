#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "bmp_peer.h"
#include "bmp_client.h"
#include "bmp_server.h"
#include "bmp_protocol.h"


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


static char * 
bmp_recv_route_monitoring(bmp_client *client, char *data, int len)
{
    bmp_peer *peer = bmp_recv_peer_hdr(client, data, len);

    if (peer == NULL) {
        
    }

    return data+len;
}


static char * 
bmp_recv_statistics_report(bmp_client *client, char *data, int len)
{
    bmp_peer *peer = bmp_recv_peer_hdr(client, data, len);

    if (peer == NULL) {
        
    }
    return data+len;
}


static char *
bmp_recv_peer_up_notification(bmp_client *client, char *data, int len)
{
    bmp_peer *peer = bmp_recv_peer_hdr(client, data, len);

    if (peer == NULL) {

    }


    return data+len;
}


static char *
bmp_recv_peer_down_notification(bmp_client *client, char *data, int len)
{
    bmp_peer *peer = bmp_recv_peer_hdr(client, data, len);

    if (peer == NULL) {

    }

    return data+len;
}


static char *
bmp_recv_initiation_message(bmp_client *client, char *data, int len)
{

    return data+len;
}


static char *
bmp_recv_termination_message(bmp_client *client, char *data, int len)
{

    return data+len;
}


static int
bmp_recv_msg_hdr(bmp_client *client, char *data, char *vers, int *len)
{
    uint8_t       type;
    uint32_t      mlen = 0;
    bmp2_msg_hdr *bmp2; // V2 header
    bmp3_msg_hdr *bmp3; // V3 header

    *vers = *data;

    switch (*vers) {
    case 2:
        /*
         * V2 is simple. No message length is declared in the header
         */
        bmp2 = (bmp2_msg_hdr*)data;
        type = bmp2->type;

        if (*len < BMP2_MSG_HDR_LEN) return BMP_MSG_HDR_WAIT;

        break;

    case 3:
        /*
         * V3 has a length field in the header. 
         */
        bmp3 = (bmp3_msg_hdr*)data;

        if (*len < BMP3_MSG_HDR_LEN) return BMP_MSG_HDR_WAIT;

        mlen = ntohl(*(uint32_t *)&bmp3->length);
        type = bmp3->type;

        if (mlen < BMP3_MSG_HDR_LEN || mlen > BMP_MSG_MAX_LEN) {
            bmp_protocol_error(client, BMP_INVALID_MSG_LENGTH);
            return BMP_MSG_HDR_ERROR;
        }

        if (*len < mlen) {
            return BMP_MSG_HDR_WAIT;
        }

        break;

    default:
        /*
         * No support for other versions
         */
        bmp_protocol_error(client, BMP_INVALID_MSG_VERSION);
        return BMP_MSG_HDR_ERROR;
        break;
    }
 
    *len = mlen;

    return (int)type;
}


static char *
bmp_recv_msg2(bmp_client *client, char *data, int type)
{
    char *end = data;

    data += BMP2_MSG_HDR_LEN;

    switch (type) {
    case BMP_ROUTE_MONITORING:
        end = bmp_recv_route_monitoring(client, data, 0);        
        break;
    case BMP_STATISTICS_REPORT:
        end = bmp_recv_statistics_report(client, data, 0);
        break;
    case BMP_PEER_DOWN_NOTIFICATION:
        end = bmp_recv_peer_down_notification(client, data, 0);
        break;
    default:
        // TODO: warning about invalid message type
        break;
    }

    return end;
}


static char *
bmp_recv_msg3(bmp_client *client, char *data, int type, int len)
{
    char *end = data;

    data += BMP3_MSG_HDR_LEN;
    len  -= BMP3_MSG_HDR_LEN;

    switch (type) {
    case BMP_ROUTE_MONITORING:
        end = bmp_recv_route_monitoring(client, data, len);        
        break;
    case BMP_STATISTICS_REPORT:
        end = bmp_recv_statistics_report(client, data, len);
        break;
    case BMP_PEER_UP_NOTIFICATION:
        end = bmp_recv_peer_up_notification(client, data, len);
        break;
    case BMP_PEER_DOWN_NOTIFICATION:
        end = bmp_recv_peer_down_notification(client, data, len);
        break;
    case BMP_INITIATION_MESSAGE:
        end = bmp_recv_initiation_message(client, data, len);
        break;
    case BMP_TERMINATION_MESSAGE:
        end = bmp_recv_termination_message(client, data, len);
        break;
    default:
        // TODO: warning about invalid message type
        break;
    }

    return end;
}


static int
bmp_recv_msg(bmp_client *client, char *data, int len)
{
    int  type;
    char vers, *end, *start = data;
 
    type = bmp_recv_msg_hdr(client, data, &vers, &len);

    if (type < 0) {
        if (type == BMP_MSG_HDR_WAIT) return 0;
        if (type == BMP_MSG_HDR_ERROR) return -1;
        assert(0);
    }

    client->server->msgs++;
    client->msgs++;
    client->mstat[type]++;

    switch (vers) {
    case 2:
        end = bmp_recv_msg2(client, data, type);
        break;
    case 3:
        end = bmp_recv_msg3(client, data, type, len);
        break;
    default:
        break;
    }

    /*
     *'start' and 'end' are pointers to the start/end of the BMP message. All 
     * that is done here is to store the message in the client's message list
     */

    //TODO: store the message in the client's message list

    return (end-start);
}


char *
bmp_recv(bmp_client *client, char *data, char *end)
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

