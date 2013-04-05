#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/time.h>

#include "bmp_log.h"
#include "bmp_util.h"
#include "bgp_peer.h"
#include "bgp_router.h"
#include "bmp_command.h"
#include "bmp_session.h"


avl_tree *bgp_router_context[BGP_ROUTER_CONTEXT_MAX];


avl_tree *
bgp_routers(int context)
{
    avl_tree *routers;

    routers = bgp_router_context[context];

    return routers;
}


int
bgp_router_compare(void *a, void *b, void *c)
{
    bgp_router *A = (bgp_router*)a;
    bgp_router *B = (bgp_router*)b;

    return bmp_sockaddr_compare(&A->addr, &B->addr, 0);
}


int
bgp_router_init()
{
    int index;
    avl_tree *tree;

    for (index = 0; index < BGP_ROUTER_CONTEXT_MAX; index++) {
        tree = avl_init(bgp_router_compare, NULL, 0);
        if (tree == NULL) {
            bmp_log("router tree init failed");
            return -1;
        }
        bgp_router_context[index] = tree;
    }

    return 0;
}


static bgp_router *
bgp_router_alloc(bmp_session *session, bmp_sockaddr *addr)
{
    bgp_router *router = calloc(1, sizeof(bgp_router));

    if (router == NULL) {
        bmp_log("bgp router alloc failed");
        return NULL;
    }

    memcpy(&router->addr, addr, sizeof(bmp_sockaddr));
    router->port = bmp_sockaddr_port(addr);
    router->session = session;

    return router;
}


static void
bgp_router_list_add(bgp_router *node, bgp_router *list)
{

}


bgp_router *
bgp_router_add(bmp_session *session, bmp_sockaddr *addr, int context)
{
    bgp_router *router, temp, *search;
    avl_tree *tree = bgp_router_context[context];

    router = bgp_router_alloc(session, addr);

    if (router == NULL) {
        return NULL;
    }

    memcpy(&temp.addr, addr, sizeof(bmp_sockaddr));
    
    search = avl_lookup(tree, &temp, NULL);

    if (search == NULL) {
        avl_insert(tree, router, NULL);
        return router;
    }
 
    /*
     * Found router is not NULL. This can happen when we are trying  to insert 
     * since we only compare routers by IP but two bgp_router objects can have 
     * the same IP but different ports. These routers sharing the same IP are 
     * chained together in a list 
     */
    bgp_router_list_add(search, router);

    return router;
}


// router search routines -----------------------------------------------------


static bgp_router *
bgp_router_list_find_walker(bgp_router *router, void *ctx)
{
    bgp_router_search_index *idx = (bgp_router_search_index *)ctx;
    
    if (router == NULL) return NULL;
    
    ++idx->index;
    
    // search by ID
    if (idx->id > 0 && idx->index == idx->id) return router;
    
    // search by port
    if (idx->port > 0) if (router->port == idx->port) return router;

    return NULL;
}


/*
 * We are looking for the list of routers with the same IP but different port
 * numbers. Make a list using the bgp_router_search_index structures as nodes
 */
static void
bgp_router_list_find_add_walker(bgp_router *router, void *ctx)
{
    bgp_router_search_index *idx = (bgp_router_search_index *)ctx;
    
    if (router == NULL) return;
    
    
    
    

}


static int
bgp_router_tree_find_walker(void *node, void *ctx)
{
    bgp_router *search, *router = (bgp_router *)node;
    bgp_router_search_index *idx = (bgp_router_search_index *)idx;
    
    while (router != NULL) {
        search = bgp_router_list_find_walker(router, ctx);
        if (search != NULL) {
            idx->router = search;
            return AVL_ERROR; // not really an error, just stop the walk
        }
        router = router->next;
        search = NULL;
    }
    return AVL_SUCCESS;
}

 
static bgp_router *
bgp_find_router_token(avl_tree *routers, 
                      char *token, 
                      bgp_router_search_index *idx)
{
    int rc, ip[4], port = 0, id = 0;
    bgp_router *router = NULL, search;

    memset(ip, 0, 16);
    memset(idx, 0, sizeof(bgp_router_search_index));

    rc = bmp_ipaddr_port_id_parse(token, ip, &port, &id);
  
    if (rc < 0) {
        return (bgp_router*)(-1); // funky!
    }

    if (id) { // return a client based on id
        idx->id = id; 
        avl_walk(routers, bgp_router_tree_find_walker, idx, AVL_WALK_INORDER);
        router = idx->router;
        idx->index = 0;
        goto done;
    }

    if (port) { // return a client based on ip + port
        bmp_sockaddr_set(&search.addr, rc, (char*) ip, port);
        idx->port = port;
        router = avl_lookup(routers, &search, NULL);
        router = bgp_router_list_find_walker(router, idx);
        idx->index = 0;
        goto done;
    }

    // return a client list based on ip (watch out for multiples)
    bmp_sockaddr_set(&search.addr, rc, (char*)ip, port);
    router = avl_lookup(routers, router, idx);
    // TODO: finish

 
done:

    return router;
}


// router show commands -------------------------------------------------------


static void
bmp_show_bgp_routers_list_walker(bgp_router *router, void *ctx)
{
    int id = ++(*((int*)ctx));
    
    char as[64];
    char up[32];
    char pe[32];
    char ms[32];
    char bs[64];

    bmp_session *session = router->session;

    snprintf(as, sizeof(as), "%s:%d", router->name, router->port);
    uptime_string(now.tv_sec - session->time.tv_sec, up, sizeof(up));
    snprintf(pe, sizeof(pe), "%d", avl_size(router->peers));
    size_string(router->msgs, ms, sizeof(ms));
    bytes_string(session->bytes, bs, sizeof(bs));

    if (id == 1) 
    dprintf(out, " ID    Address:Port               Uptime          Peers     Msgs       Data\n");
    dprintf(out, "%3d    %s%s"                      "%s%s"         "%s%s"    "%s%s"     "%s  \n", 
            id, 
            as, 
            space[26-strlen(as)], 
            up,
            space[15-strlen(up)],
            pe,
            space[9-strlen(pe)],
            ms,
            space[10-strlen(ms)], 
            bs);   
}


static int
bmp_show_bgp_routers_tree_walker(void *node, void *ctx)
{
    bgp_router *router = (bgp_router *)node;

    while (router != NULL) {
        bmp_show_bgp_routers_list_walker(router, ctx);
        router = router->next;
    }

    return AVL_SUCCESS;
}


int
bmp_show_bgp_routers()
{
    int id = 0;
    avl_tree *routers = bgp_routers(0);

    if (avl_size(routers) == 0) {
        dprintf(out, "%% No routers\n");
        return 0;
    }

    dprintf(out, "\n");
    avl_walk(routers, bmp_show_bgp_routers_tree_walker, &id, AVL_WALK_INORDER);
    dprintf(out, "\n");
    return 0;
}


int 
bmp_show_bgp_router(bgp_router *router)
{
    char up[32];
    char bs[64];

    bmp_session *session = router->session;

    assert(session != NULL);

    uptime_string(now.tv_sec - session->time.tv_sec, up, sizeof(up));
    bytes_string(session->bytes, bs, sizeof(bs));

    dprintf(out, "\n");

    dprintf(out, "BGP Router %s (port %d)\n", router->name, session->port);
    dprintf(out, "  Client up-time   : %s\n", up);
    dprintf(out, "  Total msgs rcv'd : %"PRIu64"\n", router->msgs);
    dprintf(out, "  Total data rcv'd : %s\n", bs);
    dprintf(out, "  Active BGP peers : %d\n\n", avl_size(router->peers));

    dprintf(out, "Message Statistics\n");
    dprintf(out, "  Initiation Msgs  : %"PRIu64"\n", router->mstat[BMP_INITIATION_MESSAGE]);
    dprintf(out, "  Termination Msgs : %"PRIu64"\n", router->mstat[BMP_TERMINATION_MESSAGE]);
    dprintf(out, "  Route Monitoring : %"PRIu64"\n", router->mstat[BMP_ROUTE_MONITORING]);
    dprintf(out, "  Stats Reports    : %"PRIu64"\n", router->mstat[BMP_STATISTICS_REPORT]);
    dprintf(out, "  Peer UP Notfn    : %"PRIu64"\n", router->mstat[BMP_PEER_UP_NOTIFICATION]);
    dprintf(out, "  Peer Down Notfn  : %"PRIu64"\n\n", router->mstat[BMP_PEER_DOWN_NOTIFICATION]);

    dprintf(out, "Peer Statistics\n");
    dprintf(out, "  Global peers : %d\n", 0);
    dprintf(out, "  L3VPN peers  : %d\n", 0);
    dprintf(out, "  IPv4 peers   : %d\n", 0);
    dprintf(out, "  IPv6 peers   : %d\n", 0);
    dprintf(out, "  iBGP peers   : %d\n", 0);
    dprintf(out, "  eBGP peers   : %d\n\n", 0);

    return 0;
}


static int
bmp_show_bgp_router_messages(bgp_router *router)
{

    return 0;
}


int
bmp_show_bgp_router_command(char *cmd)
{
    char *token = NULL;
    int rc = 0;
    bgp_router *router = NULL;
    bgp_router_search_index idx, *curr, *next;
    avl_tree *routers = bgp_routers(0);
    
    memset(&idx, 0, sizeof(idx));

    NEXT_TOKEN(cmd, token);

    if (!token) {
        dprintf(out, "%% Expected a keyword after 'router'\n");
        return -1;
    }

    router = bgp_find_router_token(routers, token, &idx);

    if (router == (bgp_router *)(-1)) {
        dprintf(out, "%% Invalid format '%s'\n", token);
        return -1;
    }

    if (router == NULL) {
        dprintf(out, "%% No router '%s'\n", token);
        return -1;
    }

    /*
     * More than one router found with same IP.. list them and free the list
     */
    if (router != NULL && idx.index > 1) {
        dprintf(out, "%% Multiple routers with this address:\n\n");
        for (curr = &idx; curr != NULL; curr = next) {
            next = curr->next;
            dprintf(out, "* %s:%d\n", 
                    curr->router->name, 
                    bmp_sockaddr_port(&curr->router->addr));
            if (curr != &idx) free(curr);
        }  
        dprintf(out, "\n");
        return -1;
    }

    NEXT_TOKEN(cmd, token);

    if (!token) {
        rc = bmp_show_bgp_router(router);
        return rc;
    }

    if (strcmp(token, "messages") == 0) {
        rc = bmp_show_bgp_router_messages(router);
    } else if (strcmp(token, "peers") == 0) {
        rc = bmp_show_bgp_router_peers(router);
    } else if (strcmp(token, "peer") == 0) {
        rc = bmp_show_bgp_router_peer_command(router, cmd);
    } else {
        dprintf(out, "%% Invalid keyword after 'show': %s\n", token);
    }
 
    return rc;

}


