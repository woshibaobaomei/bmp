#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/socket.h>
#include "bmp_control.h"

#define BUF_MAX 1024

int 
bmp_control_server_connect(int port)
{
    int fd, rc;
    struct sockaddr_un saddr;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);

    if (fd < 0) {
        fprintf(stderr, "%% socket() failed: %s\n", strerror(errno));
        return -1;
    }

    memset(&saddr, 0, sizeof(struct sockaddr_un));
    saddr.sun_family = AF_UNIX;
    snprintf(saddr.sun_path, sizeof(saddr.sun_path), BMP_UNIX_PATH, port);

    rc = connect(fd, (struct sockaddr *) &saddr, sizeof(struct sockaddr_un));

    if (rc < 0) {
        fprintf(stdout, "%% Could not connect to BMP server running on port: %d\n", port);
        return -1;
    }

    return fd;
}


int main(int argc, char *argv[])
{
    int index, rc, fd;
    char out[BUF_MAX], cmd[BUF_MAX], *c = cmd;

    // sanity check on first argv[0]

    // verify that argc is at least 2


    // gather info about all BMP servers running


    // parse options to see if there is a port number specified.

    // pre-parse input to see if its summary command (if so then send summary command to all running bmp servers)



    for (index = 1; index < argc; index++) 
    c += snprintf(c, sizeof(cmd), "%s ", argv[index]);
    c += snprintf(c, sizeof(cmd), "\n");

    fd = bmp_control_server_connect(1111);

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
    
 
    return 0;
}
