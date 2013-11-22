/* Copyright (c) 2013, The TCPDUMP project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>
#include "m3ua.h"

#include "interface.h"
#include "addrtoname.h"
#include "extract.h"

static const struct tok MgmtMessages[] = {
  { M3UA_MGMT_ERROR, "Error" },
  { M3UA_MGMT_NOTIFY, "Notify" },
  { 0, NULL }
};

static const struct tok TransferMessages[] = {
  { M3UA_TRANSFER_DATA, "Data" },
  { 0, NULL }
};

static const struct tok SS7Messages[] = {
  { M3UA_SSNM_DUNA, "Destination Unavailable" },
  { M3UA_SSNM_DAVA, "Destination Available" },
  { M3UA_SSNM_DAUD, "Destination State Audit" },
  { M3UA_SSNM_SCON, "Signalling Congestion" },
  { M3UA_SSNM_DUPU, "Destination User Part Unavailable" },
  { M3UA_SSNM_DRST, "Destination Restricted" },
  { 0, NULL }
};

static const struct tok ASPStateMessages[] = {
  { M3UA_ASP_UP, "Up" },
  { M3UA_ASP_DN, "Down" },
  { M3UA_ASP_BEAT, "Heartbeat" },
  { M3UA_ASP_UP_ACK, "Up Acknowledgement" },
  { M3UA_ASP_DN_ACK, "Down Acknowledgement" },
  { M3UA_ASP_BEAT_ACK, "Heartbeat Acknowledgement" },
  { 0, NULL }
};

static const struct tok ASPTrafficMessages[] = {
  { M3UA_ASP_AC, "Active" },
  { M3UA_ASP_IA, "Inactive" },
  { M3UA_ASP_AC_ACK, "Active Acknowledgement" },
  { M3UA_ASP_IA_ACK, "Inactive Acknowledgement" },
  { 0, NULL }
};

static const struct tok RoutingKeyMgmtMessages[] = {
  { M3UA_RKM_REQ, "Registration Request" },
  { M3UA_RKM_RSP, "Registration Response" },
  { M3UA_RKM_DEREQ, "Deregistration Request" },
  { M3UA_RKM_DERSP, "Deregistration Response" },
  { 0, NULL }
};

static const struct tok ParamName[] = {
  { M3UA_PARAM_INFO, "INFO String" },
  { M3UA_PARAM_ROUTING_CTX, "Routing Context" },
  { M3UA_PARAM_DIAGNOSTIC, "Diagnostic Info" },
  { M3UA_PARAM_HB_DATA, "Heartbeat Data" },
  { M3UA_PARAM_TRAFFIC_MODE_TYPE, "Traffic Mode Type" },
  { M3UA_PARAM_ERROR_CODE, "Error Code" },
  { M3UA_PARAM_STATUS, "Status" },
  { M3UA_PARAM_ASP_ID, "ASP Identifier" },
  { M3UA_PARAM_AFFECTED_POINT_CODE, "Affected Point Code" },
  { M3UA_PARAM_CORR_ID, "Correlation ID" },
  { M3UA_PARAM_NETWORK_APPEARANCE, "Network Appearance" },
  { M3UA_PARAM_USER, "User/Cause" },
  { M3UA_PARAM_CONGESTION_INDICATION, "Congestion Indications" },
  { M3UA_PARAM_CONCERNED_DST, "Concerned Destination" },
  { M3UA_PARAM_ROUTING_KEY, "Routing Key" },
  { M3UA_PARAM_REG_RESULT, "Registration Result" },
  { M3UA_PARAM_DEREG_RESUL, "Deregistration Result" },
  { M3UA_PARAM_LOCAL_ROUTING_KEY_ID, "Local Routing Key Identifier" },
  { M3UA_PARAM_DST_POINT_CODE, "Destination Point Code" },
  { M3UA_PARAM_SI, "Service Indicators" },
  { M3UA_PARAM_ORIGIN_POINT_CODE_LIST, "Originating Point Code List" },
  { M3UA_PARAM_PROTO_DATA, "Protocol Data" },
  { M3UA_PARAM_REG_STATUS, "Registration Status" },
  { M3UA_PARAM_DEREG_STATUS, "Deregistration Status" },
  { 0, NULL }
};

static void print_tag_value(const u_char *buf, u_int16_t tag, u_int16_t size)
{
  switch (tag) {
  case M3UA_PARAM_NETWORK_APPEARANCE:
  case M3UA_PARAM_ROUTING_CTX:
  case M3UA_PARAM_CORR_ID:
    printf("0x%08x", EXTRACT_32BITS(buf));
    break;
  /* ... */
  default:
    printf("(length %u)", size);
  }
}

static void print_m3ua_tags(const u_char *buf, u_int size)
{
  const u_char *p = buf;
  while (p < buf + size) {
    const struct m3ua_param_header *hdr = (const struct m3ua_param_header *) p;
    printf("\n\t\t\t%s: ", tok2str(ParamName, "Unknown Parameter (0x%04x)", EXTRACT_16BITS(&hdr->tag)));
    print_tag_value(p + sizeof(struct m3ua_param_header), EXTRACT_16BITS(&hdr->tag), EXTRACT_16BITS(&hdr->len));
    p += EXTRACT_16BITS(&hdr->len);
    int align = (int) (p - buf) % 4;
    p += (align) ? 4 - align : 0;
  }
}

void print_m3ua(const u_char *buf, u_int size)
{
  const struct m3ua_common_header *hdr = (const struct m3ua_common_header *) buf;

  printf("\n\t\t");
  switch (hdr->msg_class) {
  case M3UA_MSGC_MGMT:
    printf("Management %s Message", tok2str(MgmtMessages, "Unknown (0x%02x)", hdr->msg_type));
    break;
  case M3UA_MSGC_TRANSFER:
    printf("Transfer %s Message", tok2str(TransferMessages, "Unknown (0x%02x)", hdr->msg_type));
    break;
  case M3UA_MSGC_SSNM:
    printf("SS7 %s Message", tok2str(SS7Messages, "Unknown (0x%02x)", hdr->msg_type));
    break;
  case M3UA_MSGC_ASPSM:
    printf("ASP %s Message", tok2str(ASPStateMessages, "Unknown (0x%02x)", hdr->msg_type));
    break;
  case M3UA_MSGC_ASPTM:
    printf("ASP %s Message", tok2str(ASPTrafficMessages, "Unknown (0x%02x)", hdr->msg_type));
    break;
  case M3UA_MSGC_RKM:
    printf("Routing Key Managment %s Message",
        tok2str(RoutingKeyMgmtMessages, "Unknown (0x%02x)", hdr->msg_type));
    break;
  default:
    printf("Unknown message class %i", hdr->msg_class);
    break;
  };

  fflush(stdout);

  if (size != EXTRACT_32BITS(&hdr->len))
    printf("\n\t\t\t@@@@@@ Corrupted length %u of message @@@@@@", EXTRACT_32BITS(&hdr->len));
  else
    print_m3ua_tags(buf + sizeof(struct m3ua_common_header), EXTRACT_32BITS(&hdr->len) - sizeof(struct m3ua_common_header));
}

