#ifndef __BMP_RECV__
#define __BMP_RECV__
 
struct bmp_session_;

char *
bmp_recv(struct bmp_session_ *client, char *data, char *end);

#endif 
