#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <inttypes.h>

#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include "avl.h"
#include "bmp_log.h"
#include "bgp_peer.h"
#include "bmp_util.h"
#include "bmp_server.h"
#include "bgp_router.h"
#include "bmp_control.h"
#include "bmp_command.h"
#include "bmp_protocol.h"
 

/*
 * Command processing entry functions are implemented here. The actual routines 
 * that do the formatting of the output data are implemented by their relevant 
 * modules 
 */
 
static int
bmp_show_command(char *cmd)
{
    char *token = NULL;
    int rc = 0;

    NEXT_TOKEN(cmd, token);

    if (!token) {
        dprintf(out, "%% Expected a keyword after 'show'\n");
        return -1;
    }

    if (strcmp(token, "summary") == 0) {
    
        rc = bmp_show_summary(cmd);
        
    } else if (strcmp(token, "bgp") == 0) {

        NEXT_TOKEN(cmd, token);
    
        if (!token) {
            dprintf(out, "%% Expected a keyword after 'bgp'\n");
            return -1;
        }

        if (strcmp(token, "routers") == 0) {
            rc = bmp_show_bgp_routers();
        } else if (strcmp(token, "router") == 0) {
            rc = bmp_show_bgp_router_command(cmd);
        } else {
            dprintf(out, "%% Invalid keyword after 'bgp': %s\n", token);
        }

    } else {
        dprintf(out, "%% Invalid keyword after 'show': %s\n", token);
    }
 
    return rc;
}


static int
bmp_clear_command(char *cmd)
{
    return 0;
}


static int 
bmp_debug_command(char *cmd)
{
 
    return 0;
}

    
static int
bmp_help_command()
{


    return 0;
}


static int
bmp_command(char *cmd)
{
    char *token;
    int rc = 0;

    NEXT_TOKEN(cmd, token);

    if (!token) {
        return rc;
    } 

    if (strcmp(token, "show") == 0) {
        rc = bmp_show_command(cmd);
    } else if (strcmp(token, "clear") == 0) {
        rc = bmp_clear_command(cmd);
    } else if (strcmp(token, "debug") == 0) {
        rc = bmp_debug_command(cmd);
    } else if (strcmp(token, "help") == 0) {
        rc = bmp_help_command();
    } else {
        dprintf(out, "%% Invalid command: %s (try 'help')\n", token);
    }

    return rc;
}


// Commands Infrastructure ----------------------------------------------------


/*
 * Global variables to be used throughout the code. DO NOT REPLICATE 
 *  
 * out - Output FD for command processing.  
 * now - Current timestamp of the issued command. 
 */
int out;
struct timeval now;


/*
 * Commands event related stuff
 */
static int        bmp_command_eq;
static epv       *bmp_command_ev;
static pthread_t  bmp_command_thread;

#define BMP_COMMAND_BACKLOG 10

static int 
bmp_command_local_accept(int sock)
{
    int fd, lastfd = -1;
    struct sockaddr caddr;
    socklen_t slen = sizeof(caddr);

    while (1) {
        fd = accept(sock, &caddr, &slen); 
        if (fd < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) 
                bmp_log("accept() failed: %s", strerror(errno));
    
            break;
        } else {
            lastfd = fd;
        }
    }  

    return lastfd;
}


static int
bmp_command_process(int fd, int events)
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
        return -1;
    }
 
    buffer[rc] = 0;

    gettimeofday(&now, NULL);

    bmp_command(cmd);

    if (fd != 0) {
        close(out);
    } else {
        bmp_prompt();
    }

    return rc;
}


static void *
bmp_command_loop(void *args)
{
    int i, ev, n, fd;

    while (1) {

        n = epoll_wait(bmp_command_eq, bmp_command_ev, BMP_COMMAND_BACKLOG, -1);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            } else {
                bmp_log("epoll_wait error: %s", strerror(errno));
                return NULL;
            }
        }

        for (i = 0; i < n; i++) {
            ev = bmp_command_ev[i].events; 
            fd = bmp_command_ev[i].data.fd;
            if ((ev & EPOLLERR) || (ev & EPOLLHUP)) continue;
            bmp_command_process(fd, ev);
        }
    }

    return NULL;
}


static int
bmp_command_local_init()
{
    int fd;
    struct sockaddr_in saddr; 
    extern bmp_server server;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        bmp_log("socket call unix domain failed: %s", strerror(errno));
        return -1;
    }

    fd_nonblock(fd);
 
    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_addr.s_addr = INADDR_ANY;
    saddr.sin_port = htons(server.port + 1);
        
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
bmp_command_run()
{
    int rc;

    rc = pthread_create(&bmp_command_thread, NULL, bmp_command_loop, NULL);

    if (rc < 0) {
        bmp_log("failed to run command loop");
    }

    return 0;
}


int
bmp_command_init(int interactive)
{
    int rc = 0;
    int fd;
    struct epoll_event ev;

    /*
     * Create the epoll instance
     */
    bmp_command_eq = epoll_create(BMP_COMMAND_BACKLOG);

    if (bmp_command_eq < 0) {
        bmp_log("bmp_command_eq creation failed: %s", strerror(errno));
        return -1;
    }
    
    /*
     * Always initialize and monitor the local socket command channel
     */
    fd = bmp_command_local_init();
    
    if (fd < 0) {
        return -1;
    }

    MONITOR_FD(bmp_command_eq, fd, rc);

    if (rc < 0) {
        bmp_log("local command socket listen error: %s", fd, strerror(errno));
        return rc;
    }

    /*
     * If interactive, also monitor STDIN
     */
    if (interactive) {

        MONITOR_FD(bmp_command_eq, STDIN_FILENO, rc);
    
        if (rc < 0) {
            bmp_log("local command socket listen error: %s", fd, strerror(errno));
            return rc;
        }
    }
   
    /*
     * Allocate the command event queue
     */
    bmp_command_ev = calloc(BMP_COMMAND_BACKLOG, sizeof(ev));

    if (bmp_command_ev == NULL) {
        bmp_log("calloc(bmp_command_ev) failed");
        return -1;
    }

    return 0;
}


