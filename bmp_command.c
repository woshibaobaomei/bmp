#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/epoll.h>
#include "bmp_command.h"
#include "bmp_server.h"

static int
bmp_process_command(bmp_server *server, char *cmd, int len)
{



    return 0;
}


int
bmp_command_prompt()
{
    printf("BMP# ");
    fflush(stdout);
    return 0;
}


int
bmp_process_console(bmp_server *server, int events)
{
    char cmd[1024];
    int rc;

    rc = read(STDIN_FILENO, cmd, sizeof(cmd));
    
    if (rc > sizeof(cmd) - 1) {
        // input command is too long
    }

    cmd[rc] = 0;
    bmp_process_command(server, cmd, rc);
    

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
bmp_console_init(bmp_server *server)
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
