/*
 * Copyright (c) 2013, Petar Alilovic,
 * Faculty of Electrical Engineering and Computing, University of Zagreb
 * All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *	 this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/*
 * Structure of an NFLOG header and TLV parts, as described at
 * http://www.tcpdump.org/linktypes/LINKTYPE_NFLOG.html
 */
typedef struct nflog_hdr {
	u_int8_t	nflog_family;		/* adress family */
	u_int8_t	nflog_version;		/* version */
	u_int16_t	nflog_rid;			/* resource ID */
} nflog_hdr_t;

typedef struct nflog_tlv {
	u_int16_t	tlv_length;		/* tlv length */
	u_int16_t	tlv_type;		/* tlv type */
	void*		tlv_value;		/* tlv value */
} nflog_tlv_t;
