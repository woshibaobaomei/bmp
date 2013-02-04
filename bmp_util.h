#ifndef __BMP_UTIL_H__
#define __BMP_UTIL_H__


int bmp_log(const char *fmt, ...);
int bmp_prompt();

int bmp_so_nonblock(int fd);
int bmp_so_reuseaddr(int fd);

#endif
