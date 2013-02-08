#ifndef __BMP_UTIL_H__
#define __BMP_UTIL_H__

#include <stdint.h>
#include <netinet/in.h>

#define NEXT_TOKEN(cmd, tok)     \
do {                             \
    char *tmp = cmd;             \
    tok = cmd;                   \
    if (!*tok) {tok = 0; break;} \
    while (isspace(*tok))tok++;  \
    if (!*tok) {tok = 0; break;} \
    tmp = tok;                   \
    while (!isspace(*tmp))tmp++; \
    *tmp = 0;                    \
    cmd = tmp+1;                 \
} while (0);


typedef union bmp_sockaddr_ {
    short               af;
    struct sockaddr_in  ipv4;
    struct sockaddr_in6 ipv6;
} bmp_sockaddr;

int bmp_sockaddr_compare(bmp_sockaddr *a, bmp_sockaddr *b);
int bmp_sockaddr_string(bmp_sockaddr *a, char *buf, int len);
char *bmp_sockaddr_ip(bmp_sockaddr *a);

int fd_nonblock(int fd);
int so_reuseaddr(int fd);

int bmp_log(const char *fmt, ...);
int bmp_prompt();
int bytes_string(uint64_t bytes, char *buf, int len);


#endif
