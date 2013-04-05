#ifndef __BMP_RECV__
#define __BMP_RECV__
 
struct bmp_client_;

char *
bmp_recv(struct bmp_client_ *client, char *data, char *end);

#endif 
