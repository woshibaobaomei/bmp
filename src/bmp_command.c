#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/time.h>

#include "avl.h"
#include "bmp_util.h"
#include "bmp_control.h"
#include "bmp_command.h"
#include "bmp_server.h"
#include "bmp_client.h"

static int out;
static struct timeval now;


static int
bmp_show_summary(bmp_server *server, char *cmd)
{
    char bs[32];
    char ms[32];

    dprintf(out, "\n");
    dprintf(out, "Listening on port  : %d\n", server->port);
    dprintf(out, "Active BGP clients : %d\n", avl_size(server->clients));
    dprintf(out, "Active BGP peers   : %d\n", 0);
    size_string(server->msgs, ms, sizeof(ms), 0);
    dprintf(out, "BMP messages rcvd  : %s\n", ms);
    size_string(server->bytes, bs, sizeof(bs), 1);
    dprintf(out, "Total data rcvd    : %s\n", bs);
    size_string(server->memory, bs, sizeof(bs), 1);
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
    uptime_string(now.tv_sec - client->time.tv_sec, up, sizeof(up));
    snprintf(pe, sizeof(pe), "%d", avl_size(client->peers));
    snprintf(ms, sizeof(ms), "%llu", client->msgs);
    size_string(client->bytes, bs, sizeof(bs), 1);

    if (id == 1) 
    dprintf(out, " ID    Address:Port               Uptime          Peers     Msgs       Data\n");
    dprintf(out, "%3d    %s%s"                      "%s%s"         "%s%s"    "%s%s"     "%s  \n", 
            id, 
            as, 
            space[26-strlen(as)], 
            up,
            space[15-strlen(up)],
            pe,
            space[9-strlen(pe)],
            ms,
            space[10-strlen(ms)], 
            bs);
 
    return AVL_SUCCESS;
}


static int
bmp_show_clients(bmp_server *server, char *cmd)
{
    int id = 0;

    if (avl_size(server->clients) == 0) {
        dprintf(out, "%% No clients\n");
        return 0;
    }

    dprintf(out, "\n");
    avl_walk(&server->clients[BMP_CLIENT_ADDR], bmp_show_clients_walker, &id, 0);
    dprintf(out, "\n");
    return 0;
}


static int 
bmp_show_client(bmp_server *server, bmp_client *client)
{
    return 0;
}


static int
bmp_show_client_messages(bmp_server *server, bmp_client *client)
{

    return 0;
}


static int
bmp_show_client_peers(bmp_server *server, bmp_client *client)
{

    return 0;
}


static int
bmp_show_client_peer_command(bmp_server *server, bmp_client *client, char *cmd)
{

    return 0;
}

 
static bmp_client *
bmp_find_client_token(char *token)
{
    int  id, ip[16], port;

    if (sscanf(token, "%u.%u.%u.%u:%u", &ip[0], &ip[1], &ip[2], &ip[3], &port) == 1) {
    }

    if (sscanf(token, "%u.%u.%u.%u", &ip[0], &ip[1], &ip[2], &ip[3]) == 1) {
        // If only the IP address was specified, there is a possibility that there
        // are multiple clients with the same IP address but different port numbers.
        // In this case, we can't really do much.. the user *has* to specify the
        // port
    }

    if (sscanf(token, "%d", &id) == 1) {

    }

    return NULL;
}


static int
bmp_show_client_command(bmp_server *server, char *cmd)
{
    char *token = NULL;
    int rc = 0;
    bmp_client *client = NULL;

    NEXT_TOKEN(cmd, token);

    if (!token) {
        dprintf(out, "%% Expected a keyword after 'client'\n");
        return -1;
    }

    client = bmp_find_client_token(token);

    if (!client) {
        dprintf(out, "%% No client '%s' found", token);
        return -1;
    }

    NEXT_TOKEN(cmd, token);

    if (!token) {
        rc = bmp_show_client(server, client);
        return rc;
    }

    if (strcmp(token, "messages") == 0) {
        rc = bmp_show_client_messages(server, client);
    } else if (strcmp(token, "peers") == 0) {
        rc = bmp_show_client_peers(server, client);
    } else if (strcmp(token, "peer") == 0) {
        rc = bmp_show_client_peer_command(server, client, cmd);
    } else {
        dprintf(out, "%% Invalid keyword after 'show': %s\n", token);
    }
 
    return rc;

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
    } else if (strcmp(token, "client") == 0) {
        rc = bmp_show_client_command(server, cmd);
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

    gettimeofday(&now, NULL);

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
    struct sockaddr_in saddr; 

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        bmp_log("socket call unix domain failed: %s", strerror(errno));
        return -1;
    }

    fd_nonblock(fd);
 
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(server->port + 1);
        
    if (bind(fd, (const struct sockaddr *) &saddr, sizeof(saddr)) < 0) {
        close(fd);
        bmp_log("socket local bind failed: %s", strerror(errno));
        return -1;
    }

    if (listen(fd, 32) != 0) {
        bmp_log("socket local listen failed: %s", strerror(errno));
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

    if (fd < 0) {
        return -1;
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
