#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "msg_chunk.h"

#include "bgp_peer.h"
#include "bgp_router.h"
#include "bmp_server.h"
#include "bmp_session.h"
#include "bmp_protocol.h"



#if 0
static int 
bmp_recv_route_monitoring(bmp_client *client, char *data, int len)
{
    bmp_peer *peer = bmp_recv_peer_hdr(client, data, len);
    uint16_t bgp_walk_len, wdr_len, attr_len, nlri_len, upd_len;
    char *bgp_msg;

    bgp_walk_len = wdr_len = attr_len = nlri_len = upd_len = 0;

    if (peer == NULL) {
        
    }

    bgp_walk_len = 16;
    bgp_msg = data + BMP_PEER_HDR_COMP_LEN + bgp_walk_len;
    //TODO: check if it is an update message and only then proceed further
 
    upd_len = ntohs(*(uint16_t *)(bgp_msg));
    wdr_len = ntohs(*(uint16_t *)(bgp_msg+3));
    bgp_walk_len += 5 + wdr_len;
    attr_len = ntohs(*(uint16_t *)(bgp_msg+5+wdr_len));
    bgp_walk_len += attr_len + 2;
    nlri_len = upd_len - bgp_walk_len;

    bmp_log("bmp-msg: ROUTE-MONITORING - Update Msg Len = %d; Withdrawn Routes Len = %d; Attributes Len = %d; NLRI Len = %d", upd_len, wdr_len, attr_len, nlri_len);



    return len;
}


static int
bmp_recv_statistics_report(bmp_client *client, char *data, int len)
{
    char *bgp_msg;
    bmp_peer *peer = bmp_recv_peer_hdr(client, data, len);

    if (peer == NULL) {
        
    }

    bgp_msg = data + BMP_PEER_HDR_COMP_LEN;
 
    return len;
}


static int
bmp_recv_peer_up_notification(bmp_client *client, char *data, int len)
{
    char *bgp_msg;
    char addr[32];
    int walk_len = 0;
    uint16_t loc_port, rem_port;
    loc_port = rem_port = 0;

    bmp_peer *peer = bmp_recv_peer_hdr(client, data, len);

    if (peer == NULL) {

    }

    bgp_msg = data + BMP_PEER_HDR_COMP_LEN;

    snprintf(addr, sizeof(addr), "%u%s%u%s%u%s%u",
                             *(uint8_t *)(bgp_msg+12), ".",
                             *(uint8_t *)(bgp_msg+13), ".",
                             *(uint8_t *)(bgp_msg+14), ".",
                             *(uint8_t *)(bgp_msg+15));
    walk_len += 16;
    loc_port = ntohs(*(uint16_t *)(bgp_msg+walk_len));
    walk_len += 2;
    rem_port = ntohs(*(uint16_t *)(bgp_msg+walk_len));

    bmp_log("bmp-msg: PEER-UP - Local Addr = %s; Local Port = %d; Remote Port = %d", addr, loc_port, rem_port);

    return len;

}


static int
bmp_recv_peer_down_notification(bmp_client *client, char *data, int len)
{
    char *bgp_msg;
    bmp_peer *peer = bmp_recv_peer_hdr(client, data, len);

    if (peer == NULL) {

    }

    bgp_msg = data + BMP_PEER_HDR_COMP_LEN;

    if (*(uint8_t *)bgp_msg == 1)
        bmp_log("bmp-msg: PEER-DOWN - Reason : Local system closed the session with NOTIFICATION");
    else if (*(uint8_t *)bgp_msg == 2)
        bmp_log("bmp-msg: PEER-DOWN - Reason : Local system closed the session due to FSM Event");
    else if (*(uint8_t *)bgp_msg == 3)
        bmp_log("bmp-msg: PEER-DOWN - Reason : Remote system closed the session with NOTIFICATION");

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
#endif

static int
bmp_recv_msg_hdr(bmp_session *session, char *data, char *vers, int *len)
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
        bmp3 = (bmp3_msg_hdr*)(data);

        if (*len < BMP3_MSG_HDR_LEN) return BMP_MSG_HDR_WAIT;

        mlen = ntohl(*(uint32_t *)&bmp3->length);
        type = bmp3->type;

        if (mlen < BMP3_MSG_HDR_LEN || mlen > BMP_MSG_MAX_LEN) {
            bmp_protocol_error(session, BMP_INVALID_MSG_LENGTH);
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
        bmp_protocol_error(session, BMP_INVALID_MSG_VERSION);
        return BMP_MSG_HDR_ERROR;
        break;
    }
 
    *len = mlen;

    return (int)type;
}

#if 0
static int
bmp2_recv_msg(bmp_client *client, char *data, int type)
{
    int rc;

    data += BMP2_MSG_HDR_LEN;

    switch (type) {
    case BMP_ROUTE_MONITORING:
        rc = bmp_recv_route_monitoring(client, data, 0);        
        break;
    case BMP_STATISTICS_REPORT:
        rc = bmp_recv_statistics_report(client, data, 0);
        break;
    case BMP_PEER_DOWN_NOTIFICATION:
        rc = bmp_recv_peer_down_notification(client, data, 0);
        break;
    default:
        // TODO: warning about invalid message type
        break;
    }
 
    return rc;
}
#endif

static int
bmp3_recv_msg(bmp_session *session, char *data, int type, int len)
{
    int rc;

    return len;

    #if 0
    data += BMP3_MSG_HDR_LEN;
 
    switch (type) {
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
        break;
    }
    #endif

    return rc;
}


/*
 * The job here is to read data from the network as fast as possible and buffer 
 * the protocol data units in memory. The real job of "processing" the PDU's is 
 * done by another task. Here, all we do is parse the BMP header to figure out 
 * the message length (which is needed to copy the network buffer into memory) 
 */
static int
bmp_recv_msg(bmp_session *session, char *data, int len)
{
    int  type, rc;
    char vers;

    type = bmp_recv_msg_hdr(session, data, &vers, &len);

    if (type < 0) {
        if (type == BMP_MSG_HDR_WAIT) return 0;
        if (type == BMP_MSG_HDR_ERROR) return -1;
        assert(0);
    }

    session->server->msgs++;
    session->router->msgs++;
    session->router->mstat[type]++;

    switch (vers) {
    case 2:
        //rc = bmp2_recv_msg(session, data, type);
        break;
    case 3:
        rc = bmp3_recv_msg(session, data, type, len);
        break;
    default:
        break;
    }

    msg_add(&session->router->mhead, data, rc);

    return rc;
}


char *
bmp_recv(bmp_session *session, char *data, char *end)
{
    int rc = 1;

    while (rc > 0 && data < end) {

        rc = bmp_recv_msg(session, data, end-data);

        if (rc > 0) {
            data += rc;
        } else if (rc < 0) {
            return NULL;
        }
    }

    return data;   
}

