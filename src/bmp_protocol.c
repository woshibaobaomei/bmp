#include <unistd.h>
#include <assert.h>
#include "bmp_client.h"
#include "bmp_server.h"
#include "bmp_protocol.h"


static void
bmp_protocol_error(bmp_client *client) 
{
    /*
     * TODO: do some book-keeping here
     */

    bmp_client_close(client, BMP_CLIENT_PROTOCOL_ERROR);
}


static int 
bmp_recv_route_monitoring(bmp_client *client, char *data, int len)
{

    return len;
}


static int 
bmp_recv_statistics_report(bmp_client *client, char *data, int len)
{

    return len;
}


static int
bmp_recv_peer_up_notification(bmp_client *client, char *data, int len)
{

    return len;
}


static int 
bmp_recv_peer_down_notification(bmp_client *client, char *data, int len)
{

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

    if (mlen < BMP_MSG_HDR_LEN) {
        bmp_protocol_error(client); // invalid msg len
        return BMP_MSG_HDR_ERROR;
    }

    if (*len < mlen) {
        return BMP_MSG_HDR_WAIT;
    }

    if (vers != 3) {
        bmp_protocol_error(client); // invalid msg version
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

    client->msgs++;

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


