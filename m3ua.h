#ifndef __m3ua_h__
#define __m3ua_h__

/* RFC 4666 */

struct m3ua_common_header {
  u_int8_t  v;
  u_int8_t  reserved;
  u_int8_t  msg_class;
  u_int8_t  msg_type;
  u_int32_t len;
};

struct m3ua_param_header {
  u_int16_t tag;
  u_int16_t len;
};

/* message classes */
#define M3UA_MSGC_MGMT 0
#define M3UA_MSGC_TRANSFER 1
#define M3UA_MSGC_SSNM 2
#define M3UA_MSGC_ASPSM 3
#define M3UA_MSGC_ASPTM 4
/* reserved values */
#define M3UA_MSGC_RKM 9

/* management messages */
#define M3UA_MGMT_ERROR 0
#define M3UA_MGMT_NOTIFY 1

/* transfer messages */
#define M3UA_TRANSFER_DATA 1

/* SS7 Signaling Network Management messages */
#define M3UA_SSNM_DUNA 1
#define M3UA_SSNM_DAVA 2
#define M3UA_SSNM_DAUD 3
#define M3UA_SSNM_SCON 4
#define M3UA_SSNM_DUPU 5
#define M3UA_SSNM_DRST 6

/* ASP State Maintence messages */
#define M3UA_ASP_UP 1
#define M3UA_ASP_DN 2
#define M3UA_ASP_BEAT 3
#define M3UA_ASP_UP_ACK 4
#define M3UA_ASP_DN_ACK 5
#define M3UA_ASP_BEAT_ACK 6

/* ASP Traffic Maintence messages */
#define M3UA_ASP_AC 1
#define M3UA_ASP_IA 2
#define M3UA_ASP_AC_ACK 3
#define M3UA_ASP_IA_ACK 4

/* Routing Key Management messages */
#define M3UA_RKM_REQ 1
#define M3UA_RKM_RSP 2
#define M3UA_RKM_DEREQ 3
#define M3UA_RKM_DERSP 4

/* M3UA Parameters */
#define M3UA_PARAM_INFO 0x0004
#define M3UA_PARAM_ROUTING_CTX 0x0006
#define M3UA_PARAM_DIAGNOSTIC 0x0007
#define M3UA_PARAM_HB_DATA 0x0009
#define M3UA_PARAM_TRAFFIC_MODE_TYPE 0x000b
#define M3UA_PARAM_ERROR_CODE 0x000c
#define M3UA_PARAM_STATUS 0x000d
#define M3UA_PARAM_ASP_ID 0x0011
#define M3UA_PARAM_AFFECTED_POINT_CODE 0x0012
#define M3UA_PARAM_CORR_ID 0x0013

#define M3UA_PARAM_NETWORK_APPEARANCE 0x0200
#define M3UA_PARAM_USER 0x0204
#define M3UA_PARAM_CONGESTION_INDICATION 0x0205
#define M3UA_PARAM_CONCERNED_DST 0x0206
#define M3UA_PARAM_ROUTING_KEY 0x0207
#define M3UA_PARAM_REG_RESULT 0x0208
#define M3UA_PARAM_DEREG_RESUL 0x0209
#define M3UA_PARAM_LOCAL_ROUTING_KEY_ID 0x020a
#define M3UA_PARAM_DST_POINT_CODE 0x020b
#define M3UA_PARAM_SI 0x020c
#define M3UA_PARAM_ORIGIN_POINT_CODE_LIST 0x020e
#define M3UA_PARAM_PROTO_DATA 0x0210
#define M3UA_PARAM_REG_STATUS 0x0212
#define M3UA_PARAM_DEREG_STATUS 0x0213

#endif // __m3ua_h__
