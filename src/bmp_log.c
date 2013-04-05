#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/time.h>
#include "bmp_log.h"

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

    p += snprintf(p, sizeof(log), "[%s] ", ts);
    p += vsnprintf(p, sizeof(log)-(p-log), format, args);

    va_end(args);

    printf("%s%s%s", init ? "" : "\n", log, init ? "\n" : "");
    fflush(stdout);

    init = 0;

    return 0;
}

