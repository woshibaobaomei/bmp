#include <unistd.h>
#include "bmp_client.h"
#include "bmp_server.h"
#include "bmp_protocol.h"


static int
bmp_recv_msg_hdr(bmp_server *server, bmp_client *client, char *data, int len)
{

    return 0;
}


static int
bmp_recv_msg(bmp_server *server, bmp_client *client, char *data, int len)
{
    int rc = 0;
    int type;

    type = bmp_recv_msg_hdr(server, client, data, len);

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


