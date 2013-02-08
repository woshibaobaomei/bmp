#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include "bmp_util.h"
#include "bmp_timer.h"
#include "bmp_server.h"

/*
 * Implements a periodic timer based on alarm() and signal(). A 'SIGALRM' will
 * interrupt the BMP server asynchronously, possibly while it's in the middle 
 * of handling an event, so any real work that messes with the data cannot be 
 * done in the signal handler. What is needed, instead, is a timer that is 
 * handled as an 'fd' right  along with all the other fd's that the BMP server 
 * is waiting for in its main event loop. The timerfd_create API can be used to 
 * implement this but its not very portable, so here is an implementation that 
 * achieves pretty much the same thing using pipes which is much more portable 
 */

#define BMP_TIMERFD_MAX 8

static int init = 0;
static int timerfd[BMP_TIMERFD_MAX];
static int timerfds = 0;


static void
bmp_alarm(int signo)
{
    int index, rc;
    char ch = 0;

    for (index = 0; index < timerfds; index++) {
        rc = write(timerfd[index], &ch, 1);
        if (rc < 0) {
            bmp_log("write on timerfd failed: %s", strerror(errno));
        }
    }

    alarm(BMP_TIMER_INTERVAL);
}


static void
bmp_alarm_init()
{
    signal(SIGALRM, bmp_alarm);
    alarm(BMP_TIMER_INTERVAL);
}


int 
bmp_timer_init(bmp_server *server)
{
    int rc, timer[2];
    struct epoll_event ev;

    if (!init) {
        bmp_alarm_init();
        init = 1;
    }

    if (timerfds == BMP_TIMERFD_MAX-1) {
        bmp_log("too many timers");
        return -1;
    }

    rc = pipe(timer);

    if (rc < 0) {
        bmp_log("timer pipe init error");
        return -1;
    }
 
    rc = fd_nonblock(timer[0]);

    if (rc < 0) {
        return rc;
    }

    rc = fd_nonblock(timer[1]);

    if (rc < 0) {
        return rc;
    }

    /*
     * Register the write-end of the pipe with the timer module
     */
    timerfd[timerfds++] = timer[1];

    /*
     * Register the read-end of the pipe with the server's epoll queue
     */
    ev.data.fd = timer[0];
    ev.events = EPOLLIN | EPOLLET;
   
    rc = epoll_ctl(server->eq, EPOLL_CTL_ADD, timer[0], &ev);

    if (rc < 0) {
        bmp_log("server timer listen error: %s", timer[0], strerror(errno));
        return rc;
    }
 
    return timer[0];
}

