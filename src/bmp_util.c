#include <time.h>
#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include "bmp_log.h"
#include "bmp_util.h"
#include "bmp_server.h"

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
bmp_sockaddr_string(bmp_sockaddr *a, char *buf, int len)
{
    switch (a->af) {
    case AF_INET:
        inet_ntop(AF_INET, &a->ipv4.sin_addr, buf, len);
        break;
    case AF_INET6:
        inet_ntop(AF_INET6, &a->ipv6.sin6_addr, buf, len);
        break;
    default:
        break;
    }
    return 0;
}


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
bmp_sockaddr_compare(bmp_sockaddr *a, bmp_sockaddr *b, int pcomp)
{
    int cmp = 0;

    if (a->af != b->af) return a->af - b->af;
    
    cmp = memcmp(bmp_sockaddr_ip(a), 
                 bmp_sockaddr_ip(b), 
                 a->af == AF_INET ? 
                 sizeof(struct in_addr) :
                 sizeof(struct in6_addr));

    if (cmp) return cmp;

    if (pcomp) return bmp_sockaddr_port(a) - bmp_sockaddr_port(b);

    return cmp;
}


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


/*
 * Parse a string of the form "IP:Port" or "ID". Note that the IP address can 
 * have ":" characters (IPv6) but the separator for the port is also ":" making 
 * life more difficult 
 */
int
bmp_ipaddr_port_id_parse(char *token, int *ip, int *port, int *id)
{
    int  rc = 1, af = -1, first = 1, valid = 1;
    char temp[1024], ipstr[64];
    char *p = NULL, *q, *c = temp, *t;

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

        for (rc = -1, t = p+1; *t ; t++) 
        if (!isspace(*t) && !isdigit(*t))
        valid = 0;

        if (valid) rc = sscanf(p+1, "%d", port);
    }

noport:
 
    if (p == NULL && af != AF_INET && af != AF_INET6) {

        for (rc = -1, t = token; *t ; t++) 
        if (!isspace(*t) && !isdigit(*t))
        valid = 0;
      
        if (valid) rc = sscanf(token, "%d", id);

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
bytes_string(uint64_t size, char *buf, int len) 
{
    int rc = 0;
    char byte = 'B';

    if (size < 1<<10) { // B
        rc = snprintf(buf, len, "%"PRIu64" %c", size, byte);
    } else if (size >= 1<<10 && size < 1<<20 ) { // KB
        rc = snprintf(buf, len, "%03.2f K%c", (float)size/(float)(1<<10), byte);
    } else if (size >= 1<<20 && size < 1<<30 ) { // MB
        rc = snprintf(buf, len, "%03.2f M%c", (float)size/(float)(1<<20), byte);
    } else if (size >= 1<<30 && size < 1LLU<<40) { // GB
        rc = snprintf(buf, len, "%03.2f %s%c", (float)size/(float)(1<<30), "G", byte);
    } else { // TB
        rc = snprintf(buf, len, "%03.2f T%c", (float)size/(float)(1LLU<<40), byte);
    }

    return rc;
}


int
size_string(uint64_t size, char *buf, int len) 
{
    int rc = 0;

    if (size < 1000) { // B
        rc = snprintf(buf, len, "%"PRIu64, size);
    } else if (size >= 1000 && size < 1000000 ) { // KB
        rc = snprintf(buf, len, "%03.2f K", (float)size/(float)(1000));
    } else if (size >= 1000000 && size < 1000000000L ) { // MB
        rc = snprintf(buf, len, "%03.2f M", (float)size/(float)(1000000));
    } else if (size >= 1000000000 && size < 1000000000000L) { // GB
        rc = snprintf(buf, len, "%03.2f B", (float)size/(float)(1000000000));
    } else { // TB
        rc = snprintf(buf, len, "%03.2f T", (float)size/(float)(1000000000000L));
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


