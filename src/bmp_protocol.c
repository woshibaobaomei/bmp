#include <unistd.h>
#include <assert.h>
#include "bmp_client.h"
#include "bmp_server.h"
#include "bmp_protocol.h"


static uint8_t
bmp_recv_msg_hdr(bmp_server *server, bmp_client *client, char *data, int *len)
{
    uint32_t vers, type, mlen;
    bmp_msg_hdr *hdr = (bmp_msg_hdr*)data;

    if (*len < BMP_MSG_HDR_LEN) {
        return BMP_MSG_HDR_INCOMPLETE;
    }

    vers = hdr->version;
    mlen = GETLONG(hdr->length);
    type = hdr->type;

    //bmp_log("[%s] MESSAGE: ver: %d len: %d type: %s", client->name, vers, mlen, BMP_MESSAGE_TYPE_STRING(type));

    if (*len < mlen) {
        return BMP_MSG_HDR_INCOMPLETE;
    }

    //*len = mlen;

    return hdr->type;
}


static int
bmp_recv_msg(bmp_server *server, bmp_client *client, char *data, int len)
{
    uint8_t type;

    return len;

    type = bmp_recv_msg_hdr(server, client, data, &len);

    if (type < 0) {
        if (type == BMP_MSG_HDR_INCOMPLETE) return 0;
        if (type == BMP_MSG_HDR_ERROR) return -1;
        assert(0);
    }

    switch (type) {
    case BMP_ROUTE_MONITORING:
                
        break;
    case BMP_STATISTICS_REPORT:

        break;
    case BMP_PEER_DOWN_NOTIFICATION:

        break;
    case BMP_PEER_UP_NOTIFICATION:

        break;
    case BMP_INITIATION_MESSAGE:

        break;
    case BMP_TERMINATION_MESSAGE:

        break;
    default:
        break;
    }
 
    return len;
}

char *
bmp_protocol_read(bmp_server *server, bmp_client *client, char *data, char *end)
{
    int rc = 1;

    while (rc > 0 && data < end) {

        rc = bmp_recv_msg(server, client, data, end-data);

        if (rc > 0) {
            data += rc;
        } else if (rc < 0) {
            return NULL;
        }
    }

    return data;   
}


