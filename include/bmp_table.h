
#define BMP_TABLE_IPv4_UNICAST 0
#define BMP_TABLE_IPv6_UNICAST 1
#define BMP_TABLE_IPv4_LABEL   2
#define BMP_TABLE_IPv6_LABEL   3
#define BMP_TABLE_IPv4_VPN     4
#define BMP_TABLE_IPv6_VPN     6

typedef struct bgp_attr_ {

} bgp_attr;


typedef struct bgp_rd_ {
    radix_node rn;
    uint8_t    rd[8];
    radix_head routes;
} bgp_rd;


typedef struct bmp_table_ {
    radix_head rd;
} bmp_table;

typedef struct bgp_path_adv_ {
    bmp_peer   *peer;
    bgp_attr    attr[0];
} bgp_path_adv;


typedef struct bgp_route_ {
    radix_node    rn;
    bgp_adv_list *adv;
    uint8_t       network[0];
} bgp_route;

 
#define BMP_AF_TABLE(af, saf) 
