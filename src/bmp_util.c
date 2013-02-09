#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "bmp_util.h"


int 
bmp_sockaddr_string(bmp_sockaddr *a, char *buf, int len)
{
    int port;

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

char *
bmp_sockaddr_ip(bmp_sockaddr *a)
{
    switch (a->af) {
    case AF_INET:
        return (char*)&a->ipv4.sin_addr;
    case AF_INET6:
        return (char*)&a->ipv6.sin6_addr;
    default:
        break;
    }
    return NULL;
}

uint16_t
bmp_sockaddr_port(bmp_sockaddr *a)
{
    switch (a->af) {
    case AF_INET:
        return a->ipv4.sin_port;
    case AF_INET6:
        return a->ipv6.sin6_port;
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

    p += snprintf(p, sizeof(log), "BMP# [%s] ", ts);
    p += vsnprintf(p, sizeof(log)-(p-log), format, args);

    va_end(args);

    printf("%s%s%s", init ? "" : "\n", log, init ? "\n" : "");
    fflush(stdout);
   
    if (init) bmp_prompt();

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
bytes_string(uint64_t bytes, char *buf, int len) 
{
    int rc = 0;

    if (bytes < 1<<10) { // B
        rc = snprintf(buf, len, "%llu B", bytes);
    } else if (bytes >= 1<<10 && bytes < 1<<20 ) { // KB
        rc = snprintf(buf, len, "%03.2f KB", (float)bytes/(float)(1<<10));
    } else if (bytes >= 1<<20 && bytes < 1<<30 ) { // MB
        rc = snprintf(buf, len, "%03.2f MB", (float)bytes/(float)(1<<20));
    } else if (bytes >= 1<<30 && bytes < 1LLU<<40) { // GB
        rc = snprintf(buf, len, "%03.2f GB", (float)bytes/(float)(1<<30));
    } else { // TB
        rc = snprintf(buf, len, "%03.2f TB", (float)bytes/(float)(1LLU<<40));
    }

    return rc;
}

