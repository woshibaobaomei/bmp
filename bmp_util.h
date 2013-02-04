#ifndef __BMP_UTIL_H__
#define __BMP_UTIL_H__


#define NEXT_TOKEN(cmd, tok)     \
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


int socket_nonblock(int fd);
int socket_reuseaddr(int fd);

int bmp_log(const char *fmt, ...);
int bmp_prompt();


#endif
