#ifndef __BMP_CLIENT_H__
#define __BMP_CLIENT_H__

#include <sys/time.h>
 

#define BMP_CLIENT_MAX     (1 << 10)
#define BMP_RDBUF_MAX      (1 << 16) 
#define BMP_RDBUF_SPACE(c) ((c)->rdbuf+BMP_RDBUF_MAX-(c)->rdptr)
 
typedef struct bmp_server_  bmp_server;
typedef struct bmp_message_ bmp_message;
typedef struct bmp_client_  bmp_client;

/*
 * The bmp_client type represents a BGP speaker that has connected to us and 
 * is sending us data it receives (BGP updates) from its connected peers.  
 */
struct bmp_client_ {
    int   fd;
    char *rdptr;
    char  rdbuf[BMP_RDBUF_MAX];
        
    bmp_message *head;
    bmp_message *tail;
};

 
struct bmp_message_ {
    struct timeval time;
    bmp_message   *next;
    unsigned char  data[0];
};


int bmp_create_client(bmp_server *server, int fd);
int bmp_process_client(bmp_server *server, int fd, int events);
int bmp_close_client(bmp_server *server, bmp_client *client, int reason);

#endif

