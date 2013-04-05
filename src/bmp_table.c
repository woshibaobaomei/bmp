#include "bmp_table.h"
#include "bgp_router.h"


int 
bmp_table_init()
{
    int rc;

    rc = bgp_router_init();

    if (rc < 0) {
        return -1;
    }

    // TODO: initialize more table related stuff

    return 0;
}

