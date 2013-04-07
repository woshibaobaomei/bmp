#ifndef __BGP_TABLE_H__
#define __BGP_TABLE_H__

#include <stdint.h>
#include "radix.h"
#include "bgp_peer.h"

#define BGP_IPv4_UCAST 0
#define BGP_IPv6_UCAST 1
#define BGP_IPv4_LABEL 2
#define BGP_IPv6_LABEL 3
#define BGP_IPv4_VPN   4
#define BGP_IPv6_VPN   6
#define BGP_AF_MAX     7

typedef struct radix_head *rhead;
typedef struct radix_node  radix;

typedef struct bgp_attr_ {

} bgp_attr;


typedef struct bgp_rd_ {
    radix   rn;
    uint8_t rd[8];
    rhead   routes;
} bgp_rd;


typedef struct bmp_table_ {
    rhead     rd;
} bmp_table;

typedef struct bgp_path_adv_ {
    bgp_peer  *peer;
    char       attr[0];
} bgp_path_adv;

typedef struct bgp_adv_list_ {


} bgp_adv_list;

typedef struct bgp_route_ {
    radix         rn;
    bgp_adv_list *adv;
    uint8_t       network[0];
} bgp_route;


int bmp_table_init(int af);


#endif
 
