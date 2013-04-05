#ifndef __BMP_PROTOCOL_H__
#define __BMP_PROTOCOL_H__

#include <stdint.h>
 
#define BMP_ROUTE_MONITORING       0
#define BMP_STATISTICS_REPORT      1
#define BMP_PEER_DOWN_NOTIFICATION 2
#define BMP_PEER_UP_NOTIFICATION   3
#define BMP_INITIATION_MESSAGE     4
#define BMP_TERMINATION_MESSAGE    5
#define BMP_MESSAGE_TYPE_MAX       6


#define BMP_MESSAGE_TYPE_STRING(t)                              \
  (t == BMP_ROUTE_MONITORING       ? "Route Monitoring"       : \
   t == BMP_STATISTICS_REPORT      ? "Statistics Report"      : \
   t == BMP_PEER_DOWN_NOTIFICATION ? "Peer Down Notification" : \
   t == BMP_PEER_UP_NOTIFICATION   ? "Peer Up Notification"   : \
   t == BMP_INITIATION_MESSAGE     ? "Initiation Message"     : \
   t == BMP_TERMINATION_MESSAGE    ? "Termination Message"    : \
                                     "Unknown")                 \


#define BMP_PEER_TYPE_GLOBAL 0
#define BMP_PEER_TYPE_L3VPN  1
#define BMP_PEER_FLAG_V      0x01  // IPv6
#define BMP_PEER_FLAG_L      0x02  // Loc-RIB


/*
 *   0 1 2 3 4 5 6 7 8 
 *   +-+-+-+-+-+-+-+-+
 *   |    Version    |
 *   +---------------+
 *   |   Msg. Type   |
 *   +---------------+
 */
typedef struct bmp2_msg_hdr_ {
    uint8_t version;
    uint8_t type;
} bmp2_msg_hdr;


#if 0
/*   0 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |    Version    |        Message Length         |    Msg. Type  |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct bmp3_msg_hdr_ {
    uint8_t version;
    uint8_t length[2];
    uint8_t type;
} bmp3_msg_hdr;
#endif


/*
 *   0 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
 *   +-+-+-+-+-+-+-+-+
 *   |    Version    |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                        Message Length                         |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Msg. Type   |
 *   +---------------+
 */

typedef struct bmp3_msg_hdr_ {
    uint8_t version;
    uint8_t length[4];
    uint8_t type;
} bmp3_msg_hdr;


/*
 *   0 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |   Peer Type   |  Peer Flags   |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         Peer Distinguisher (present based on peer type)       |
 *   |                                                               |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                 Peer Address (16 bytes)                       |
 *   ~                                                               ~
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                           Peer AS                             |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                         Peer BGP ID                           |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                    Timestamp (seconds)                        |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                  Timestamp (microseconds)                     |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct bmp_peer_hdr_ {
    uint8_t type;
    uint8_t flags;
    uint8_t rd[8];
    uint8_t addr[16];
    uint8_t asn[4];
    uint8_t id[4];
    uint8_t tv_sec[4];
    uint8_t tv_msec[4];
} bmp_peer_hdr;


typedef struct bmp_initiation_msg_ {
    
} bmp3_initiation_msg;


typedef struct bmp_termination_msg_ {

} bmp_termination_msg;


/*
 *   0 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                 Local Address (16 bytes)                      |
 *   ~                                                               ~
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |         Local Port            |        Remote Port            |
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                    Sent OPEN Message                          |
 *   ~                                                               ~
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |                  Received OPEN Message                        |
 *   ~                                                               ~
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct bmp_peer_up_msg_ {
    uint8_t      laddr[16];
    uint8_t      lport[2];
    uint8_t      fport[2];
    uint8_t      open_msg[0];
} bmp_peer_up_msg;


/*
 *   0 1 2 3 4 5 6 7 8
 *   +-+-+-+-+-+-+-+-+
 *   |    Reason     | 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8 1 2 3 4 5 6 7 8
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *   |            Data (present if Reason = 1, 2 or 3)               |
 *   ~                                                               ~
 *   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
typedef struct bmp_peer_down_msg_ {
    uint8_t      reason;
    uint8_t      data[0];
} bmp_peer_down_msg;


//-----------------------------------------------------------------------------

#define BMP_MSG_MAX_LEN   (1<<14)

#define BMP2_MSG_HDR_LEN  ( 2)
#define BMP3_MSG_HDR_LEN  ( 4)

#define BMP_MSG_HDR_WAIT  (-1)
#define BMP_MSG_HDR_ERROR (-2)
#define BMP_MSG_RM_ERROR  (-3)

#define BMP_INVALID_MSG_VERSION  0
#define BMP_INVALID_MSG_LENGTH   1
#define BMP_INVALID_MSG_TYPE     2
#define BMP_INVALID_RM_MSG	 3


#endif

