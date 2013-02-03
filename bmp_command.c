#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/epoll.h>
#include "bmp_command.h"
#include "bmp_server.h"


#define BMP_NEXT_TOKEN(cmd, tok) \
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



static int
bmp_show_summary(bmp_server *server, char *cmd)
{
 
    return 0;
}



static int
bmp_show_clients(bmp_server *server, char *cmd)
{
 
    return 0;
}


static int
bmp_show_command(bmp_server *server, char *cmd)
{
    char *token = NULL;
    int rc = 0;

    BMP_NEXT_TOKEN(cmd, token);

    if (!token) {
        printf("%% Expected a keyword after 'show'\n");
        return -1;
    }

    if (strcmp(token, "bmp") == 0) {

        BMP_NEXT_TOKEN(cmd, token);

        if (!token) {
            printf("%% Expected a keyword after 'show bmp'\n");
            return -1;
        }

        if (strcmp(token, "summary") == 0) {
            rc = bmp_show_summary(server, cmd);
        } else if (strcmp(token, "clients") == 0) {
            rc = bmp_show_clients(server, cmd);
        } else {
            printf("%% Invalid keyword after 'show bmp': %s\n", token);
            return -1;
        }

    } else {
        printf("%% Invalid keyword after 'show': %s\n", token);
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

    BMP_NEXT_TOKEN(cmd, token);

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
        printf("%% Invalid command: %s (try 'help')\n", token);
    }

    return rc;
}


int
bmp_command_prompt()
{
    printf("BMP# ");
    fflush(stdout);
    return 0;
}


int
bmp_command_process(bmp_server *server, int events)
{
    char buffer[1024], *cmd = buffer;
    int rc;

    rc = read(STDIN_FILENO, buffer, sizeof(buffer));
    
    if (rc > sizeof(buffer) - 1) {
        // input command is too long
    }
 
    buffer[rc] = 0;

    bmp_command(server, cmd);

    bmp_command_prompt();

    return rc;
}

#if 0
void
bmp_process_console2(bmp_server *server, int events)
{
    int rc;
    char c[16], ch;
    rc = read(0, c, 16);
    ch = c[0];
    c[rc] = 0;
  
    if (ch == 13) {

        printf("\r\n");
        bmp_console_prompt();

    } else if (ch == 127) {

        printf("\b \b");
        fflush(stdout);

    } else {

        printf("%d.%d ", ch, rc);
        fflush(stdout);

    }
}
#endif


int
bmp_command_init(bmp_server *server)
{
    int rc = 0;
    struct epoll_event ev;

#if 0
    struct termios tio;
    tio.c_lflag &=(~ICANON & ~ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &tio);
#endif


    ev.data.fd = STDIN_FILENO;
    ev.events = EPOLLIN | EPOLLET;
   
    rc = epoll_ctl(server->eq, EPOLL_CTL_ADD, STDIN_FILENO, &ev);

    if (rc < 0) {
        bmp_log("epoll_ctl(EPOLL_CTL_ADD, %d) failed: %s", STDIN_FILENO, strerror(errno));
        return rc;
    }

    return rc;
}
