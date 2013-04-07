#include <string.h>
#include "avl.h"
#include "bmp_log.h"
#include "bgp_router.h"
#include "bmp_context.h"


static bmp_context bmp_contexts[BMP_CONTEXT_MAX];


int
bmp_context_init(int context)
{
    avl_tree *tree;
    int af, rc;

    /*
     * Initialize the BMP tables
     */
    for (af = 0; af < BGP_AF_MAX; af++) {
        rc = bmp_table_init(af);
        if (rc < 0 ) {
            bmp_log("bmp table init failed for af %d", af);
            return -1;
        }
    }
    
    /*
     * Initialize the BMP routers
     */
    tree = avl_init(bgp_router_compare, NULL, AVL_TREE_INTRUSIVE);

    if (tree == NULL) {
        bmp_log("failed to initialize routers tree");
        return -1;
    }

    bmp_contexts[context].bgp_routers = tree;

    return 0;
}


avl_tree *
bmp_context_routers(int context)
{
    return bmp_contexts[context].bgp_routers;
}

