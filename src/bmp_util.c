#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "bmp_util.h"

#define SPC  " "
#define SPC2 SPC  SPC
#define SPC3 SPC2 SPC
#define SPC4 SPC3 SPC
#define SPC5 SPC4 SPC
#define SPC6 SPC5 SPC
#define SPC7 SPC6 SPC
#define SPC8 SPC7 SPC
#define SPC9 SPC8 SPC


char *space[] = { 
    SPC, 
    SPC2, 
    SPC3, 
    SPC4, 
    SPC5, 
    SPC6, 
    SPC7, 
    SPC8, 
    SPC9,
    SPC9 SPC, 
    SPC9 SPC2, 
    SPC9 SPC3, 
    SPC9 SPC4,
    SPC9 SPC5, 
    SPC9 SPC6,
    SPC9 SPC7,
    SPC9 SPC8,
    SPC9 SPC9
};


int
bmp_ipaddr_string(uint8_t *a, int af, char *buf, int len)
{
    switch (af) {
    case AF_INET:
        inet_ntop(AF_INET, a, buf, len);
        break;
    case AF_INET6:
        inet_ntop(AF_INET6, a, buf, len);
        break;
    default:
        break;
    }
    return 0;
}


int 
bmp_sockaddr_string(bmp_sockaddr *a, char *buf, int len)
{
    int port = 0;

    switch (a->af) {
    case AF_INET:
        inet_ntop(AF_INET, &a->ipv4.sin_addr, buf, len);
        port = a->ipv4.sin_port;
        break;
    case AF_INET6:
        inet_ntop(AF_INET6, &a->ipv6.sin6_addr, buf, len);
        port = a->ipv6.sin6_port;
        break;
    default:
        break;
    }
    return port;
}


#define bmp_sockaddr_ip(a)         \
        (a->af == AF_INET ?        \
        (void*)&a->ipv4.sin_addr : \
        (void*)&a->ipv6.sin6_addr)


#define bmp_sockaddr_port(a) \
        (a->af == AF_INET ?  \
         a->ipv4.sin_port :  \
         a->ipv6.sin6_port)


int 
bmp_sockaddr_set(bmp_sockaddr *a, int af, char *ip, int port)
{
    a->af = af;
    switch (af) {
    case AF_INET:
        memcpy(&a->ipv4.sin_addr, ip, 4);
        a->ipv4.sin_port = port;
    case AF_INET6:
        memcpy(&a->ipv6.sin6_addr, ip, 16);
        a->ipv6.sin6_port = port;
    default:
        break;
    }
    return 0;
}


int 
bmp_sockaddr_compare(bmp_sockaddr *a, bmp_sockaddr *b)
{
    int cmp;

    if (a->af != b->af) return a->af - b->af;
    
    cmp = memcmp(bmp_sockaddr_ip(a), 
                 bmp_sockaddr_ip(b), 
                 a->af == AF_INET ? 
                 sizeof(struct in_addr) :
                 sizeof(struct in6_addr));

    if (cmp) return cmp;

    return bmp_sockaddr_port(a) - bmp_sockaddr_port(b);
}


/*
 * Parse a string of the form "IP:Port" or "ID". Note that the IP address can 
 * have ":" characters (IPv6) but the separator for the port is also ":" making 
 * life more difficult 
 */
int
bmp_ipaddr_port_id_parse(char *token, int *ip, int *port, int *id)
{
    int  rc = 1, af = -1, first = 1;
    char temp[1024], ipstr[64], *p = NULL, *q, *c = temp;

    memset(temp, 0, sizeof(temp));
    memset(ipstr, 0, sizeof(ipstr));
    memcpy(temp, token, strlen(token));

    /*
     * Find the last ":" in the token
     */
    q = strchr(temp, ':');
     
    while (q != NULL) {
        p = q;
        q = strchr(q+1, ':');
    }

    if (p != NULL) temp[p-c] = 0;

parseip:
    
    if (inet_pton(AF_INET, temp, ip) == 1) {
        af = AF_INET;
    } else {
        if (inet_pton(AF_INET6, temp, ip) == 1) { 
            af = AF_INET6;
        }
    }

    if (af != AF_INET && af != AF_INET6 && first) {
        first = 0;
        memcpy(temp, token, strlen(token));
        goto parseip;
    }
    
    if (p) {
        if (af == AF_INET6 && !first) goto noport;
        rc = sscanf(p+1, "%d", port);
    }

noport:
 
    if (p == NULL && af != AF_INET && af != AF_INET6) {
        rc = sscanf(token, "%d", id);
    } else if ( p && af != AF_INET && af != AF_INET6) {
        rc = -1;
    }
 
    if (rc != 1) {
        return -1;
    } 

    if (af > 0) {
        return af;
    }

    return 0;
}


int
bmp_prompt()
{
    printf("BMP# ");
    fflush(stdout);
    return 0;
}


int
bmp_log(const char *format, ...) 
{
    char log[1024];
    char ts[64];
    char *t = ts;
    char *p = log;
    struct timeval tv; 
    struct tm *tm;
    static int init = 1;

    gettimeofday(&tv, NULL);
    tm = localtime(&tv.tv_sec);
    t += strftime(t, sizeof(ts), "%H:%M:%S.", tm);
    snprintf(t, sizeof(ts), "%03ld", tv.tv_usec/1000);

    va_list args;
    va_start(args, format);

    p += snprintf(p, sizeof(log), "[%s] ", ts);
    p += vsnprintf(p, sizeof(log)-(p-log), format, args);

    va_end(args);

    printf("%s%s%s", init ? "" : "\n", log, init ? "\n" : "");
    fflush(stdout);

    init = 0;

    return 0;
}


int 
fd_nonblock(int fd)
{
    int flags, rc;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        bmp_log("fcntl(%d, F_GETFL) failed: %s", fd, strerror(errno));
        return -1;
    }

    flags |= O_NONBLOCK;
    rc = fcntl(fd, F_SETFL, flags);
    if (rc < 0) {
        bmp_log("fcntl(%d, F_SETFL) failed: %s", fd, strerror(errno));
        return -1;
    }

    return 0;
}


int 
so_reuseaddr(int fd)
{
    int rc, optv;

    rc = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optv, sizeof(optv));

    if (rc < 0) {
        bmp_log("SO_REUSEADDR(%d) failed: %s", fd, strerror(errno));
    }

    return rc;
}


int
size_string(uint64_t size, char *buf, int len, int bytes) 
{
    int rc = 0;
    char byte = bytes ? 'B' : ' ';

    if (size < 1<<10) { // B
        rc = snprintf(buf, len, "%llu %c", size, byte);
    } else if (size >= 1<<10 && size < 1<<20 ) { // KB
        rc = snprintf(buf, len, "%03.2f K%c", (float)size/(float)(1<<10), byte);
    } else if (size >= 1<<20 && size < 1<<30 ) { // MB
        rc = snprintf(buf, len, "%03.2f M%c", (float)size/(float)(1<<20), byte);
    } else if (size >= 1<<30 && size < 1LLU<<40) { // GB
        rc = snprintf(buf, len, "%03.2f %s%c", (float)size/(float)(1<<30), bytes ? "G" : "B" , byte);
    } else { // TB
        rc = snprintf(buf, len, "%03.2f T%c", (float)size/(float)(1LLU<<40), byte);
    }

    return rc;
}


int 
uptime_string(int s, char *buf, int len)
{
    if (s < 86400) { // 01:20:23
        snprintf(buf, len, "%02d:%02d:%02d", s/3600, s/60 % 60, s % 60);
    } else if (s >= 86400) { // 2d 10h 2m
        snprintf(buf, len, "%dd %dh %dm", s/86400, s/3600 % 24, s/60 % 60);
    }

    return s;
}


int
cmdexec(char *cmd, char *buf, int len)
{
    FILE *file;
    char *ptr = buf;
    int rc = 1;

    memset(buf, 0, len);

    if ((file = popen(cmd, "r")) == NULL) {
        return -1;
    }

    while ((rc = read(fileno(file), ptr, len-(ptr-buf))) > 0) {
        ptr += rc;
        if (ptr - buf > len) break;
    }
  
    return rc;
}


char *bmp_optarg = NULL;


char *
bmp_getopt(int argc, char *argv[], int *index)
{
    char *curr = NULL;
    char *next = NULL;
    bmp_optarg = NULL;

    if (*index < argc) {
        curr = argv[*index];
        if (curr != NULL && *curr == '-' && strlen(curr) > 1) {
            if (*index < argc - 1) {
                next = argv[*index + 1];
            }
            if (next != NULL  && *next != '-') {
                bmp_optarg = next;
                (*index)++;
            }
            curr++;
            (*index)++;
        } else {
           /*
            * Option processing error
            */
            curr = NULL;
        }
    }

    return curr;
}


void
bmp_ungetopt(int *index)
{
    (*index) -= (bmp_optarg ? 2 : 1);
}


