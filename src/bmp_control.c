#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/socket.h>
#include "bmp_util.h"
#include "bmp_control.h"

/*
 * Each BMP server opens a listen socket for handling client connections on 
 * port N and also opens a listen socket for handling control commands on 
 * port N+1. So every instance of the server will have 2 listen sockets open. 
 * The bmp_server_listen_ports returns an array containing all the listening 
 * ports for all server instances that are running: 
 *  
 * [ Client Port #1, Control Port #1, Client Port #2, Control Port #2, ... ]
 */
#define BMP_LISTEN_PORTS_CMD                            \
"ps -e              | grep %s     | awk '{print $1}' |" \
"xargs -n1 lsof -Pp | grep LISTEN | awk '{print $9}' |" \
"cut -d ':' -f 2-2 2> /dev/null"

static int 
bmp_server_listen_ports(int *ports, int len)
{
    char cmd[1024], buf[1024], *ptr;
    int  rc, port, n = 0;

    snprintf(cmd, sizeof(cmd), BMP_LISTEN_PORTS_CMD, "bmp");

    cmdexec(cmd, buf, sizeof(buf));

    ptr = strtok(buf, "\n");

    while (ptr) {
        rc = sscanf(ptr, "%d", &port);
        if (rc <= 0) {
            return -1;
        }
        ports[n++] = port;
        if (n == len) {
            //
        }
        ptr = strtok(NULL, "\n");
    }

    return n;
}


static int ports[100];
static int nport = 0;

int 
bmp_control_init()
{
    nport = bmp_server_listen_ports(ports, 100);

    if (nport == 0) {
        fprintf(stdout, "%% No BMP servers running\n");
        return -1;
    }

    if (nport % 2 != 0) {
        fprintf(stdout, "%% Internal error\n");
        return -1;
    }

    return 0;
}


int 
bmp_control_server_connect(int port)
{
    int fd, rc;
    struct sockaddr_in saddr;

    fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        fprintf(stderr, "%% socket() failed: %s\n", strerror(errno));
        return -1;
    }

    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    saddr.sin_port = htons(port);

    rc = connect(fd, (struct sockaddr *) &saddr, sizeof(struct sockaddr_in));

    if (rc < 0) {
        fprintf(stdout, "%% Could not connect to server on port: %d\n", port);
        return -1;
    }

    return fd;
}


#define BUF_MAX 1024

static int 
bmp_control(int argc, char *argv[], int cport)
{
    int index, rc, fd;
    char out[BUF_MAX], cmd[BUF_MAX], *c = cmd;

    for (index = 1; index < argc; index++) 
    c += snprintf(c, sizeof(cmd), "%s ", argv[index]);
    c += snprintf(c, sizeof(cmd), "\n");

    fd = bmp_control_server_connect(cport);

    if (fd < 0) {
        return -1;
    }

    rc = write(fd, cmd, strlen(cmd));

    if (rc < 0) {
        return -1;
    }

    while (1) {
        rc = read(fd, out, sizeof(out)-1);
        if (rc <= 0) break;
        out[rc] = 0;
        printf("%s", out);
    }

    close(fd);

    return 0;
}


/*
 * Iterate over the list of servers and do a "show summary" for them
 */
static void
bmp_control_show_summaries(int argc, char *argv[])
{
    int i;

    for (i = 0; i < nport; i++) {
        bmp_control(argc, argv, ports[++i]);
    }
}


int 
bmp_control_run(int argc, char *argv[])
{
    int i, rc, port = 0, found = 0;

    /*
     * Pre-parse options to see if this is the "bmp show summary" command
     */ 
    if (argc == 3) {
        if (strcmp(argv[1], "show") == 0 &&
            strcmp(argv[2], "summary") == 0) {
            bmp_control_show_summaries(argc, argv);
            return 0;
        }
    }

    /* 
     * If there are more than one servers running, port must be specified
     */
    rc = sscanf(argv[1], "%d", &port);
    if (rc <= 0) port = 0;
    if (rc <= 0 && nport > 2) {
        fprintf(stderr, "%% Multiple servers - specify port after 'bmp'\n\n");
        for (i = 0; i < nport; i++) {
            fprintf(stderr, "* %d\n", ports[i++]);
        }
        fprintf(stderr, "\n");
        return -1;
    }

    /*
     * Verify specified port, if any
     */
    if (port != 0) {
        for (i = 0; i < nport; i++) {
            if (port == ports[i++]) {
                found = 1; 
                break;
            }
        }

        if (!found) {
            fprintf(stderr, "%% No server running on port: %d\n", port);
            return -1;
        }

        argv[1] = " ";
    } else {
        port = ports[0];
    }

    /*
     * Issue the command to the right server
     */
    bmp_control(argc, argv, port+1);

    return 0;
}

#if 0
int main(int argc, char *argv[])
{

    // sanity check on first argv[0]

    // verify that argc is at least 2


    // gather info about all BMP servers running


    // parse options to see if there is a port number specified.

    // pre-parse input to see if its summary command (if so then send summary command to all running bmp servers)



 
    return 0;
}
#endif
