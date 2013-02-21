#ifndef __BMP_UTIL_H__
#define __BMP_UTIL_H__

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>

extern char *space[];

#define GETLONG(b)  ntohl(*((uint32_t*)(b)))
#define GETSHORT(b) ntohs(*((uint16_t*)(b)))

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
    union {
        struct sockaddr_in  ipv4;
        struct sockaddr_in6 ipv6;
    };
} bmp_sockaddr;


#define bmp_sockaddr_ip(a)         \
        (a->af == AF_INET ?        \
        (void*)&a->ipv4.sin_addr : \
        (void*)&a->ipv6.sin6_addr)


#define bmp_sockaddr_port(a)   \
        ((a)->af == AF_INET ?  \
         (a)->ipv4.sin_port :  \
         (a)->ipv6.sin6_port)


int bmp_sockaddr_set(bmp_sockaddr *a, int af, char *ip, int port);
int bmp_sockaddr_compare(bmp_sockaddr *a, bmp_sockaddr *b, int pcomp);
int bmp_sockaddr_string(bmp_sockaddr *a, char *buf, int len);

int bmp_ipaddr_port_id_parse(char *token, int *ip, int *port, int *id);
int bmp_ipaddr_string(uint8_t *a, int af, char *buf, int len);

int fd_nonblock(int fd);
int so_reuseaddr(int fd);

int bmp_log(const char *fmt, ...);
int bmp_prompt();
int size_string(uint64_t size, char *buf, int len);
int bytes_string(uint64_t size, char *buf, int len);
int uptime_string(int s, char *buf, int len);
int cmdexec(char *cmd, char *buf, int len);

extern char *bmp_optarg;
char *bmp_getopt(int argc, char *argv[], int *index);
void bmp_ungetopt(int *index);

#endif
