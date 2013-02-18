#ifndef __BMP_CONTROL_H__
#define __BMP_CONTROL_H__

#define BMP_UNIX_PATH "bmpd-%d"

int bmp_control_init();
int bmp_control_run(int argc, char *argv[]);


#endif
