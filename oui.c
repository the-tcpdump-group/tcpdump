/* 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code
 * distributions retain the above copyright notice and this paragraph
 * in its entirety, and (2) distributions including binary code include
 * the above copyright notice and this paragraph in its entirety in
 * the documentation or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND
 * WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
 * LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE.
 *
 * Original code by Hannes Gredler (hannes@juniper.net)
 */

#ifndef lint
static const char rcsid[] _U_ =
    "@(#) $Header: /tcpdump/master/tcpdump/oui.c,v 1.1 2003-11-26 08:49:14 hannes Exp $ (LBL)";
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>
#include "interface.h"
#include "oui.h"


/* list taken from ethereal/packet-radius.c */

struct tok oui_values[] = {
    { OUI_ACC,                  "ACC"},
    { OUI_CISCO,                "Cisco"},
    { OUI_SHIVA,                "Shiva"},
    { OUI_MICROSOFT,            "Microsoft"},
    { OUI_LIVINGSTON,           "Livingston"},
    { OUI_3COM,                 "3Com"},
    { OUI_ASCEND,               "Ascend"},
    { OUI_BAY,                  "Bay Networks"},
    { OUI_FOUNDRY,              "Foundry"},
    { OUI_VERSANET,             "Versanet"},
    { OUI_REDBACK,              "Redback"},
    { OUI_JUNIPER,              "Juniper Networks"},
    { OUI_APTIS,                "Aptis"},
    { OUI_COSINE,               "CoSine Communications"},
    { OUI_SHASTA,               "Shasta"},
    { OUI_NOMADIX,              "Nomadix"},
    { OUI_UNISPHERE,            "Unisphere Networks"},
    { OUI_ISSANNI,              "Issanni Communications"},
    { OUI_QUINTUM,              "Quintum"},
    { OUI_COLUBRIS,             "Colubris"},
    { OUI_COLUMBIA_UNIVERSITY,  "Columbia University"},
    { OUI_THE3GPP,              "3GPP"},
    { 0, NULL }
};
