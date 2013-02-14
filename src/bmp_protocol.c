#include <unistd.h>
#include "bmp_client.h"
#include "bmp_server.h"
#include "bmp_protocol.h"


static uint8_t
bmp_recv_msg_hdr(bmp_server *server, bmp_client *client, char *data, int len)
{
    bmp_msg_hdr *hdr = (bmp_msg_hdr*)data;
    return hdr->type;
}


static int
bmp_recv_msg(bmp_server *server, bmp_client *client, char *data, int len)
{
    uint8_t type;

    type = bmp_recv_msg_hdr(server, client, data, len);

    bmp_log("[%d:%d] message from %s", type, len, client->name);

    switch (type) {
    case 0:
        
    case 1:
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


