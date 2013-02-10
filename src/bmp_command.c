#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/un.h>
#include <sys/epoll.h>

#include "avl.h"
#include "bmp_util.h"
#include "bmp_control.h"
#include "bmp_command.h"
#include "bmp_server.h"

static int out;


static int
bmp_show_summary(bmp_server *server, char *cmd)
{
    char bs[32];

    dprintf(out, "\n");
    dprintf(out, "Listening on port  : %d\n", server->port);
    dprintf(out, "Active BGP clients : %d\n", avl_size(server->clients));
    dprintf(out, "Active BGP peers   : %d\n", 0);
    dprintf(out, "BMP messages rcvd  : %d\n", 0);
    bytes_string(server->bytes, bs, sizeof(bs));
    dprintf(out, "Total data rcvd    : %s\n", bs);
    bytes_string(server->memory, bs, sizeof(bs));
    dprintf(out, "Total memory usage : %s\n", bs);       

    dprintf(out, "\n");

    return 0;
}


static int
bmp_show_clients_walker(void *node, void *ctx)
{
    int id = ++(*((int*)ctx));

    char as[64];
    char up[32];
    char pe[32];
    char ms[32];
    char bs[64];

    bmp_client *client = node;
    snprintf(as, sizeof(as), "%s:%d", client->name, client->port);
    snprintf(up, sizeof(up), "00:00:00");
    snprintf(pe, sizeof(pe), "%d", avl_size(client->peers));
    snprintf(ms, sizeof(ms), "%llu", client->msgs);
    bytes_string(client->bytes, bs, sizeof(bs));

    if (id == 1) 
    dprintf(out, " ID    Address:Port               Uptime          Peers     Msgs      Data\n");
    dprintf(out, "%3d    %s%s"                      "%s%s"         "%s%s"    "%s%s"    "%s  \n", 
            id, 
            as, 
            space[26-strlen(as)], 
            up,
            space[15-strlen(up)],
            pe,
            space[9-strlen(pe)],
            ms,
            space[9-strlen(ms)], 
            bs);
 
    return AVL_SUCCESS;
}


static int
bmp_show_clients(bmp_server *server, char *cmd)
{
    int id = 0;

    if (avl_size(server->clients) == 0) return 0;

    dprintf(out, "\n");
    avl_walk(&server->clients[BMP_CLIENT_ADDR], bmp_show_clients_walker, &id, 0);
    dprintf(out, "\n");
    return 0;
}


static int
bmp_show_command(bmp_server *server, char *cmd)
{
    char *token = NULL;
    int rc = 0;

    NEXT_TOKEN(cmd, token);

    if (!token) {
        dprintf(out, "%% Expected a keyword after 'show'\n");
        return -1;
    }

    if (strcmp(token, "summary") == 0) {
        rc = bmp_show_summary(server, cmd);
    } else if (strcmp(token, "clients") == 0) {
        rc = bmp_show_clients(server, cmd);
    } else {
        dprintf(out, "%% Invalid keyword after 'show': %s\n", token);
    }
 
    return rc;
}


static int
bmp_clear_command(bmp_server *server, char *cmd)
{
    return 0;
}


static int 
bmp_debug_command(bmp_server *server, char *cmd)
{
 
    return 0;
}

    
static int
bmp_help_command()
{


    return 0;
}


static int
bmp_command(bmp_server *server, char *cmd)
{
    char *token;
    int rc = 0;

    NEXT_TOKEN(cmd, token);

    if (!token) {
        return rc;
    } 

    if (strcmp(token, "show") == 0) {
        rc = bmp_show_command(server, cmd);
    } else if (strcmp(token, "clear") == 0) {
        rc = bmp_clear_command(server, cmd);
    } else if (strcmp(token, "debug") == 0) {
        rc = bmp_debug_command(server, cmd);
    } else if (strcmp(token, "help") == 0) {
        rc = bmp_help_command();
    } else {
        dprintf(out, "%% Invalid command: %s (try 'help')\n", token);
    }

    return rc;
}


// Commands Infrastructure ----------------------------------------------------


static int 
bmp_command_local_accept(int sock)
{
    int fd;
    struct sockaddr caddr;
    socklen_t slen;

    while (1) {

        slen = sizeof(caddr);

        fd = accept(sock, &caddr, &slen); 

        if (fd > 0) return fd;

        if (errno == EAGAIN || errno == EWOULDBLOCK) break;

        bmp_log("accept() failed: %s", strerror(errno));

        return -1;
    }  

    return -1;
}


int
bmp_command_process(bmp_server *server, int fd, int events)
{
    char buffer[1024], *cmd = buffer;
    int in, rc;

    /*
     * If the commands are coming from stdin (interactive), pipe the output to 
     * stdout. Otherwise, we are getting command requests from the local socket 
     * and we have to accept the connection and write to the accepted fd 
     */
    if (fd == 0) {
        in = 0;
        out = 1;
    } else {
        out = bmp_command_local_accept(fd);
        in = out;
    }

    rc = read(in, buffer, sizeof(buffer)-1);

    if (rc < 0) {
        bmp_log("command read error: %d (%s)", strerror(errno));
    }
 
    buffer[rc] = 0;

    bmp_command(server, cmd);

    if (fd != 0) {
        close(out);
    } else {
        bmp_prompt();
    }

    return rc;
}


static int
bmp_command_local_init(bmp_server *server)
{
    int fd;
    struct sockaddr_un saddr; 

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        bmp_log("socket call unix domain failed: %s", strerror(errno));
        return -1;
    }

    fd_nonblock(fd);
 
    memset(&saddr, 0, sizeof(saddr));
    saddr.sun_family = AF_UNIX;
    snprintf(saddr.sun_path, sizeof(saddr.sun_path), BMP_UNIX_PATH, server->port);
 
    unlink(saddr.sun_path);       
    if (bind(fd, (const struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
        close(fd);
        bmp_log("socket unix domain bind failed: %s", strerror(errno));
        return -1;
    }

    if (listen(fd, 32) != 0) {
        bmp_log("socket unix domain listen failed: %s", strerror(errno));
    }

    return fd;
}


int
bmp_command_init(bmp_server *server, int interactive)
{
    int rc = 0;
    int fd;
    struct epoll_event ev;
 
    if (interactive) {
        fd = STDIN_FILENO;
    } else {
        fd = bmp_command_local_init(server);
    }
    
    ev.data.fd = fd;
    ev.events = EPOLLIN | EPOLLET;
   
    rc = epoll_ctl(server->eq, EPOLL_CTL_ADD, fd, &ev);

    if (rc < 0) {
        bmp_log("epoll_ctl(EPOLL_CTL_ADD, %d) failed: %s", fd, strerror(errno));
        return rc;
    }

    return fd;
}
