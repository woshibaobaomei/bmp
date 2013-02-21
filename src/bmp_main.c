#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "bmp_util.h"
#include "bmp_timer.h"
#include "bmp_server.h"
#include "bmp_control.h"

enum {
    BMP_CONTROL,
    BMP_SERVER,
    BMP_HELP
};


static void 
print_help()
{
    printf("\n");
    printf("Usage:\n\n");
    printf("  * bmp -s <port> (server mode)\n");
    printf("  * bmp <command> (control mode)\n");
    printf("\n");
    printf("Server Mode Options:\n\n");
    printf("  * interactive : -i (default: no)\n");
    printf("  * log-file    : -l <file>\n");
    printf("  * data dir.   : -d <directory>\n");
    printf("  * quiet       : -q (default: no)\n");
    printf("\n");
    printf("Control Mode Commands:\n\n");
    printf("  * show summary\n");
    printf("  * show clients\n");
    printf("  * show client <client>\n"); 
    printf("  * show client <client> messages\n");
    printf("  * show client <client> peers\n");
    printf("  * show client <client> peer <peer>\n");
    printf("  * show client <client> peer <peer> messages\n");
    printf("\n");
}



int main(int argc, char *argv[])
{
    char *opt;
    int optindex = 1;

    int rc = 0;
    int mode = BMP_SERVER;
    int interactive = 0;
    int port = 0;
    int timer;

    while ((opt = bmp_getopt(argc, argv, &optindex)) != NULL) {

        if (strcmp(opt, "p") == 0 || strcmp(opt, "s") == 0 || strcmp(opt, "port") == 0) {

            mode = BMP_SERVER;

            if (bmp_optarg == NULL) {
                fprintf(stderr, "%% Port number expected after '-%s'\n", opt);
                return -1;
            }

            if (sscanf(bmp_optarg, "%d", &port) <= 0) {
                fprintf(stderr, "%% Port number format error after '-%s'\n", opt);
                return -1;
            }

        } else if (strcmp(opt, "i") == 0 || strcmp(opt, "interactive") == 0) {

            interactive = 1;

        } else if (strcmp(opt, "h") == 0 || strcmp(opt, "help") == 0) {

            mode = BMP_HELP;

        }
    }

    if (optindex < argc) {
        mode = BMP_CONTROL;
    }

    // Help
    if (argc == 1 || mode == BMP_HELP) {
        print_help();
        return 0;
    }
    
    // Control
    if (mode == BMP_CONTROL) {
        rc = bmp_control_init();

        if (rc < 0) {
            return -1;
        }

        rc = bmp_control_run(argc, argv);

        return rc;
    } 

    // Server
    if (mode == BMP_SERVER) {

        if (port == 0) {
            fprintf(stderr, "%% Server listen port must be specified with '-s' option\n");
            return -1;
        }

        if (port < 200 || port > 65000) {
            fprintf(stderr, "%% Server listen port number '%d' invalid\n", port);
            return -1;
        }

        timer = bmp_timer_init();

        if (timer < 0) {
            bmp_log("Timer init failed");
            return -1;
        }

        rc = bmp_server_init(port, timer, interactive); 

        if (rc < 0) {
            return -1;
        }

        bmp_log("Listening on port: %d", port);

        if (!interactive) {
            rc = daemon(1, 1);
        }

        if (rc < 0) {
            bmp_log("Server detatch from shell failed");
            return -1;
        }

        rc = bmp_server_run();
    }

    return rc;
}

