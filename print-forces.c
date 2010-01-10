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
 * Copyright (c) 2009 Mojatatu Networks, Inc
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#include <stdio.h>
#include <stdlib.h>

#include "interface.h"
#include "extract.h"

#include "forces.h"

#define RESLEN	4

int
prestlv_print(register const u_char * pptr, register u_int len,
	      u_int16_t op_msk, int indent)
{
	struct forces_tlv *tlv = (struct forces_tlv *)pptr;
	register const u_char *tdp = (u_char *) TLV_DATA(tlv);
	struct res_val *r = (struct res_val *)tdp;
	u_int32_t allres = (u_int32_t) * (u_char *) TLV_DATA(tlv);
	u_int16_t dlen = len - TLV_HDRL;

	if (dlen != RESLEN) {
		printf("illegal RESULT-TLV: %d bytes! \n", dlen);
		return -1;
	}

	if (r->result >= 0x18 && r->result <= 0xFE) {
		printf("illegal reserved result code: 0x%x! \n", r->result);
		return -1;
	}

	if (vflag >= 3) {
		char *ib = indent_pr(indent, 0);
		printf("%s  Result: %s (code 0x%x)\n", ib,
		       tok2str(ForCES_errs, NULL, r->result), r->result);
	}
	return 0;
}

int
fdatatlv_print(register const u_char * pptr, register u_int len,
	       u_int16_t op_msk, int indent)
{
	struct forces_tlv *tlv = (struct forces_tlv *)pptr;
	u_int tll = len - TLV_HDRL;
	register const u_char *tdp = (u_char *) TLV_DATA(tlv);
	u_int16_t type = ntohs(tlv->type);
	if (type != F_TLV_FULD) {
		printf("Error: expecting FULLDATA!\n");
		return -1;
	}

	if (vflag >= 3) {
		char *ib = indent_pr(indent + 2, 1);
		printf("%s[", &ib[1]);
		hex_print_with_offset(ib, tdp, tll, 0);
		printf("\n%s]\n", &ib[1]);
	}
	return 0;
}

int
sdatailv_print(register const u_char * pptr, register u_int len,
	       u_int16_t op_msk, int indent)
{
	int tll = len - ILV_HDRL;
	struct forces_ilv *ilv = (struct forces_ilv *)pptr;
	int invilv;

	indent += 1;
	while (1) {
		invilv = ilv_valid(ilv, tll);
		if (invilv) {
			printf("Error: BAD ILV!\n");
			return -1;
		}
		if (vflag >= 3) {
			register const u_char *tdp = (u_char *) ILV_DATA(ilv);
			char *ib = indent_pr(indent, 1);
			printf("\n%s SPARSEDATA: type %x length %d\n", &ib[1],
			       ntohl(ilv->type), ntohl(ilv->length));
			printf("%s[", &ib[1]);
			hex_print_with_offset(ib, tdp, tll, 0);
			printf("\n%s]\n", &ib[1]);
		}

		ilv = GO_NXT_ILV(ilv, tll);
	}

	return 0;
}

int
sdatatlv_print(register const u_char * pptr, register u_int len,
	       u_int16_t op_msk, int indent)
{
	struct forces_tlv *tlv = (struct forces_tlv *)pptr;
	u_int tll = len - TLV_HDRL;
	register const u_char *tdp = (u_char *) TLV_DATA(tlv);
	u_int16_t type = ntohs(tlv->type);
	if (type != F_TLV_SPAD) {
		printf("Error: expecting SPARSEDATA!\n");
		return -1;
	}

	return sdatailv_print(tdp, tll, op_msk, indent);
}

int
pkeyitlv_print(register const u_char * pptr, register u_int len,
	       u_int16_t op_msk, int indent)
{
	struct forces_tlv *tlv = (struct forces_tlv *)pptr;
	register const u_char *tdp = (u_char *) TLV_DATA(tlv);
	register const u_char *dp = tdp + 4;
	struct forces_tlv *kdtlv = (struct forces_tlv *)dp;
	u_int32_t id = EXTRACT_32BITS(tdp);
	char *ib = indent_pr(indent, 0);
	u_int16_t type, tll;
	int invtlv;

	printf("%sKeyinfo: Key 0x%x\n", ib, id);
	type = ntohs(kdtlv->type);
	invtlv = tlv_valid(kdtlv, len);

	if (invtlv) {
		printf("%s TLV type 0x%x len %d\n",
		       tok2str(ForCES_TLV_err, NULL, invtlv), type,
		       ntohs(kdtlv->length));
		return -1;
	}
	tll = ntohs(kdtlv->length);
	dp = (u_char *) TLV_DATA(kdtlv);
	return fdatatlv_print(dp, tll, op_msk, indent);
}

int
pdatacnt_print(register const u_char * pptr, register u_int len,
	       u_int32_t IDcnt, u_int16_t op_msk, int indent)
{
	int i;
	int rc;
	u_int32_t id;
	char *ib = indent_pr(indent, 0);

	for (i = 0; i < IDcnt; i++) {
		id = EXTRACT_32BITS(pptr);
		if (vflag >= 3)
			printf("%s  ID#%02d: %d\n", ib, i + 1, id);
		len -= 4;
		pptr += 4;
	}
	if (len) {
		struct forces_tlv *pdtlv = (struct forces_tlv *)pptr;
		u_int16_t type = ntohs(pdtlv->type);
		u_int16_t tll = ntohs(pdtlv->length) - TLV_HDRL;
		register const u_char *dp = (u_char *) TLV_DATA(pdtlv);
		int pad = 0;
		int aln = F_ALN_LEN(ntohs(pdtlv->length));

		int invtlv = tlv_valid(pdtlv, len);

		if (invtlv) {
			printf
			    ("%s Outstanding bytes %d for TLV type 0x%x TLV len %d\n",
			     tok2str(ForCES_TLV_err, NULL, invtlv), len, type,
			     ntohs(pdtlv->length));
			goto pd_err;
		}
		if (aln > ntohs(pdtlv->length)) {
			if (aln > len) {
				printf
				    ("Invalid padded pathdata TLV type 0x%x len %d missing %d pad bytes\n",
				     type, ntohs(pdtlv->length), aln - len);
			} else {
				pad = aln - ntohs(pdtlv->length);
			}
		}
		if (pd_valid(type)) {
			struct pdata_ops *ops = get_forces_pd(type);

			if (vflag >= 3 && ops->v != F_TLV_PDAT) {
				if (pad)
					printf
					    ("%s %s (Length %d DataLen %d pad %d Bytes)\n",
					     ib, ops->s, ntohs(pdtlv->length),
					     tll, pad);
				else
					printf
					    ("%s  %s (Length %d DataLen %d Bytes)\n",
					     ib, ops->s, ntohs(pdtlv->length),
					     tll);
			}

			chk_op_type(type, op_msk, ops->op_msk);

			rc = ops->print((const u_char *)pdtlv,
					tll + pad + TLV_HDRL, op_msk,
					indent + 2);
		} else {
			printf("Invalid path data content type 0x%x len %d\n",
			       type, ntohs(pdtlv->length));
pd_err:
			if (ntohs(pdtlv->length)) {
				hex_print_with_offset("Bad Data val\n\t  [",
						      pptr, len, 0);
				printf("]\n");

				return -1;
			}
		}
	}
	return 0;
}

int
pdata_print(register const u_char * pptr, register u_int len,
	    u_int16_t op_msk, int indent)
{
	struct pathdata_h *pdh = (struct pathdata_h *)pptr;
	char *ib = indent_pr(indent, 0);
	int minsize = 0;
	if (vflag >= 3) {
		printf("\n%sPathdata: Flags 0x%x ID count %d\n",
		       ib, ntohs(pdh->pflags), ntohs(pdh->pIDcnt));
	}

	if (ntohs(pdh->pflags) & F_SELKEY) {
		op_msk |= B_KEYIN;
	}
	pptr += sizeof(struct pathdata_h);
	len -= sizeof(struct pathdata_h);
	minsize = ntohs(pdh->pIDcnt) * 4;
	if (len < minsize) {
		printf("\t\t\ttruncated IDs expectd %dB got %dB\n", minsize,
		       len);
		hex_print_with_offset("\t\t\tID Data[", pptr, len, 0);
		printf("]\n");
		return -1;
	}
	return pdatacnt_print(pptr, len, ntohs(pdh->pIDcnt), op_msk, indent);
}

int
genoptlv_print(register const u_char * pptr, register u_int len,
	       u_int16_t op_msk, int indent)
{
	struct forces_tlv *pdtlv = (struct forces_tlv *)pptr;
	u_int16_t type = ntohs(pdtlv->type);
	int tll = ntohs(pdtlv->length) - TLV_HDRL;
	int invtlv = tlv_valid(pdtlv, len);
	char *ib = indent_pr(indent, 0);
	struct optlv_h *ops;
	int rc = 0;

	printf("genoptlvprint - %s TLV type 0x%x len %d\n",
	       tok2str(ForCES_TLV, NULL, type), type, ntohs(pdtlv->length));
	if (!invtlv) {
		register const u_char *dp = (u_char *) TLV_DATA(pdtlv);
		if (!ttlv_valid(type)) {
			printf("%s TLV type 0x%x len %d\n",
			       tok2str(ForCES_TLV_err, NULL, invtlv), type,
			       ntohs(pdtlv->length));
			return -1;
		}
		if (vflag >= 3)
			printf("%s%s, length %d (data length %d Bytes)",
			       ib, tok2str(ForCES_TLV, NULL, type),
			       ntohs(pdtlv->length), tll);

		return pdata_print(dp, tll, op_msk, indent + 1);
	} else {
		printf("\t\t\tInvalid ForCES TLV type=%x", type);
		return -1;
	}
}

int
recpdoptlv_print(register const u_char * pptr, register u_int len,
		 u_int16_t op_msk, int indent)
{
	struct forces_tlv *pdtlv = (struct forces_tlv *)pptr;
	int tll = len;
	int rc = 0;
	int invtlv;
	u_int16_t type;
	register const u_char *dp;
	char *ib;

	while (1) {
		invtlv = tlv_valid(pdtlv, len);
		if (invtlv) {
			break;
		}
		ib = indent_pr(indent, 0);
		type = ntohs(pdtlv->type);
		dp = (u_char *) TLV_DATA(pdtlv);
		tll = ntohs(pdtlv->length) - TLV_HDRL;

		if (vflag >= 3)
			printf
			    ("%s%s, length %d (data encapsulated %d Bytes)",
			     ib, tok2str(ForCES_TLV, NULL, type),
			     ntohs(pdtlv->length),
			     ntohs(pdtlv->length) - TLV_HDRL);

		rc = pdata_print(dp, tll, op_msk, indent + 1);
		pdtlv = GO_NXT_TLV(pdtlv, len);
	}

	if (len) {
		printf
		    ("\n\t\tMessy PATHDATA TLV header, type (0x%x) \n\t\texcess of %d Bytes ",
		     ntohs(pdtlv->type), tll - ntohs(pdtlv->length));
		return -1;
	}

	return 0;
}

int
invoptlv_print(register const u_char * pptr, register u_int len,
	       u_int16_t op_msk, int indent)
{
	char *ib = indent_pr(indent, 1);
	if (vflag >= 3) {
		printf("%sData[", &ib[1]);
		hex_print_with_offset(ib, pptr, len, 0);
		printf("%s]\n", ib);
	}
	return -1;
}

int otlv_print(struct forces_tlv *otlv, u_int16_t op_msk, int indent)
{
	int rc = 0;
	register const u_char *dp = (u_char *) TLV_DATA(otlv);
	u_int16_t type = ntohs(otlv->type);
	int tll = ntohs(otlv->length) - TLV_HDRL;
	char *ib = indent_pr(indent, 0);
	struct optlv_h *ops;
	struct pathdata_h *pdh;

	ops = get_forces_optlv_h(type);
	if (vflag >= 3) {
		printf("%sOper TLV %s(0x%x) length %d\n", ib, ops->s, type,
		       ntohs(otlv->length));
	}
	//empty TLVs like COMMIT and TRCOMMIT are empty, we stop here ..
	if (!ops->flags & ZERO_TTLV) {
		if (tll != 0)	// instead of "if (tll)" - for readability ..
			printf("%s: Illegal - MUST be empty\n", ops->s);
		return rc;
	}
	// rest of ops must at least have 12B {pathinfo}
	if (tll < OP_MIN_SIZ) {
		printf("\t\tOper TLV %s(0x%x) length %d\n", ops->s, type,
		       ntohs(otlv->length));
		printf("\t\tTruncated data size %d minimum required %d\n", tll,
		       OP_MIN_SIZ);
		return invoptlv_print(dp, tll, ops->op_msk, indent);

	}

	rc = ops->print(dp, tll, ops->op_msk, indent + 1);
	return rc;
}

#define ASTDLN	4
#define ASTMCD	255
int
asttlv_print(register const u_char * pptr, register u_int len,
	     u_int16_t op_msk, int indent)
{

	u_int32_t rescode;
	u_int16_t dlen = len - TLV_HDRL;
	char *ib = indent_pr(indent, 0);
	if (dlen != ASTDLN) {
		printf("illegal ASTresult-TLV: %d bytes! \n", dlen);
		return -1;
	}
	rescode = EXTRACT_32BITS(pptr);
	if (rescode > ASTMCD) {
		printf("illegal ASTresult result code: %d! \n", rescode);
		return -1;
	}

	if (vflag >= 3) {
		printf("Teardown reason: \n%s", ib);
		switch (rescode) {
		case 0:
			printf("Normal Teardown");
			break;
		case 1:
			printf("Loss of Heartbeats");
			break;
		case 2:
			printf("Out of bandwidth");
			break;
		case 3:
			printf("Out of Memory");
			break;
		case 4:
			printf("Application Crash");
			break;
		default:
			printf("Unknown Teardown reason");
			break;
		}
		printf("(%x) \n%s", rescode, ib);
	}
	return 0;
}

#define ASRDLN	4
#define ASRMCD	3
int
asrtlv_print(register const u_char * pptr, register u_int len,
	     u_int16_t op_msk, int indent)
{

	u_int32_t rescode;
	u_int16_t dlen = len - TLV_HDRL;
	char *ib = indent_pr(indent, 0);

	if (dlen != ASRDLN) {	// id, instance, oper tlv
		printf("illegal ASRresult-TLV: %d bytes! \n", dlen);
		return -1;
	}
	rescode = EXTRACT_32BITS(pptr);

	if (rescode > ASRMCD) {
		printf("illegal ASRresult result code: %d! \n", rescode);
		return -1;
	}

	if (vflag >= 3) {
		printf("\n%s", ib);
		switch (rescode) {
		case 0:
			printf("Success ");
			break;
		case 1:
			printf("FE ID invalid ");
			break;
		case 2:
			printf("permission denied ");
			break;
		default:
			printf("Unknown ");
			break;
		}
		printf("(%x) \n%s", rescode, ib);
	}
	return 0;
}

int
gentltlv_print(register const u_char * pptr, register u_int len,
	       u_int16_t op_msk, int indent)
{
	u_int16_t dlen = len - TLV_HDRL;
	if (dlen < 4) {		/* at least 32 bits must exist */
		printf("truncated TLV: %d bytes missing! ", 4 - dlen);
		return -1;
	}
	return 0;
}

#define RD_MIN 8
int
print_metailv(register const u_char * pptr, register u_int len,
	      u_int16_t op_msk, int indent)
{
	u_int16_t dlen = len - ILV_HDRL;
	int tll = dlen;
	char *ib = indent_pr(indent, 0);
	//XXX: check header length
	struct forces_ilv *ilv = (struct forces_ilv *)pptr;
	printf("\n%sMetaID 0x%x length %d\n", ib, ntohl(ilv->type),
	       ntohl(ilv->length));
	hex_print_with_offset("\n\t\t\t\t[", (char *)ILV_DATA(ilv), tll, 0);
	return 0;
}

int
print_metatlv(register const u_char * pptr, register u_int len,
	      u_int16_t op_msk, int indent)
{
	u_int16_t dlen = len - TLV_HDRL;
	char *ib = indent_pr(indent, 0);
	int tll = dlen;
	struct forces_ilv *ilv = (struct forces_ilv *)pptr;
	int invilv;

	printf("\n%s METADATA \n", ib);
	while (1) {
		invilv = ilv_valid(ilv, tll);
		if (invilv)
			break;
		print_metailv((u_char *) ilv, tll, 0, indent + 1);

		ilv = GO_NXT_ILV(ilv, tll);
	}

	return 0;
}

/*
*/
int
print_reddata(register const u_char * pptr, register u_int len,
	      u_int16_t op_msk, int indent)
{
	u_int16_t dlen = len - TLV_HDRL;
	int tll = dlen;
	int invtlv;
	struct forces_tlv *tlv = (struct forces_tlv *)pptr;

	printf("\n\t\t Redirect DATA\n");
	if (dlen <= RD_MIN) {
		printf("\n\t\ttruncated Redirect data: %d bytes missing! ",
		       RD_MIN - dlen);
		return -1;
	}

	invtlv = tlv_valid(tlv, tll);

	if (invtlv) {
		printf("Redir data type 0x%x len %d\n", ntohs(tlv->type),
		       ntohs(tlv->length));
		return -1;
	}

	tll -= TLV_HDRL;
	hex_print_with_offset("\n\t\t\t[", (char *)TLV_DATA(tlv), tll, 0);
	return 0;
}

int
redirect_print(register const u_char * pptr, register u_int len,
	       u_int16_t op_msk, int indent)
{
	struct forces_tlv *tlv = (struct forces_tlv *)pptr;
	u_int16_t dlen = len - TLV_HDRL;
	int tll = dlen;
	int invtlv;

	if (dlen <= RD_MIN) {
		printf("\n\t\ttruncated Redirect TLV: %d bytes missing! ",
		       RD_MIN - dlen);
		return -1;
	}

	indent += 1;
	while (1) {
		invtlv = tlv_valid(tlv, tll);
		if (invtlv)
			break;
		if (ntohs(tlv->type) == F_TLV_METD) {
			print_metatlv((u_char *) TLV_DATA(tlv), tll, 0, indent);
		} else if ((ntohs(tlv->type) == F_TLV_REDD)) {
			print_reddata((u_char *) TLV_DATA(tlv), tll, 0, indent);
		} else {
			printf("Unknown REDIRECT TLV 0x%x len %d\n",
			       ntohs(tlv->type), ntohs(tlv->length));
		}

		tlv = GO_NXT_TLV(tlv, tll);
	}

	if (tll) {
		printf
		    ("\n\t\tMessy Redirect TLV header, type (0x%x) \n\t\texcess of %d Bytes ",
		     ntohs(tlv->type), tll - ntohs(tlv->length));
		return -1;
	}

	return 0;
}

#define OP_OFF 8
#define OP_MIN 12

int
lfbselect_print(register const u_char * pptr, register u_int len,
		u_int16_t op_msk, int indent)
{
	const struct forces_lfbsh *lfbs;
	struct forces_tlv *otlv;
	char *ib = indent_pr(indent, 0);
	u_int16_t dlen = len - TLV_HDRL;
	int tll = dlen - OP_OFF;
	int invtlv;

	if (dlen <= OP_MIN) {	// id, instance, oper tlv header ..
		printf("\n\t\ttruncated lfb selector: %d bytes missing! ",
		       OP_MIN - dlen);
		return -1;
	}

	lfbs = (const struct forces_lfbsh *)pptr;
	if (vflag >= 3) {
		printf("\n%s%s(Classid %x) instance %x\n",
		       ib, tok2str(ForCES_LFBs, NULL, ntohl(lfbs->class)),
		       ntohl(lfbs->class), ntohl(lfbs->instance));
	}

	otlv = (struct forces_tlv *)(lfbs + 1);

	indent += 1;
	while (1) {
		invtlv = tlv_valid(otlv, tll);
		if (invtlv)
			break;
		if (op_valid(ntohs(otlv->type), op_msk)) {
			otlv_print(otlv, 0, indent);
		} else {
			if (vflag < 3)
				printf("\n");
			printf
			    ("\t\tINValid oper-TLV type 0x%x length %d for this ForCES message\n",
			     ntohs(otlv->type), ntohs(otlv->length));
			invoptlv_print((char *)otlv, tll, 0, indent);
		}
		otlv = GO_NXT_TLV(otlv, tll);
	}

	if (tll) {
		printf
		    ("\n\t\tMessy oper TLV header, type (0x%x) \n\t\texcess of %d Bytes ",
		     ntohs(otlv->type), tll - ntohs(otlv->length));
		return -1;
	}

	return 0;
}

int
forces_type_print(register const u_char * pptr, const struct forcesh *fhdr,
		  register u_int mlen, struct tom_h *tops)
{
	struct forces_tlv *tltlv;
	int tll;
	int invtlv;
	int rc = 0;
	int ttlv = 0;
	int len = mlen;

	tll = mlen - sizeof(struct forcesh);

	if (tll > TLV_HLN) {
		if (tops->flags & ZERO_TTLV) {
			printf("<0x%x>Illegal Top level TLV!\n", tops->flags);
			return -1;
		}
	} else {
		if (tops->flags & ZERO_MORE_TTLV)
			return 0;
		if (tops->flags & ONE_MORE_TTLV) {
			printf("\tTop level TLV Data missing!\n");
			return -1;
		}
	}

	if (tops->flags & ZERO_TTLV) {
		return 0;
	}

	ttlv = tops->flags >> 4;
	tltlv = GET_TOP_TLV(pptr);

	/*XXX: 15 top level tlvs will probably be fine
	   You are nuts if you send more ;-> */
	while (1) {
		invtlv = tlv_valid(tltlv, tll);
		if (invtlv)
			break;
		if (!ttlv_valid(ntohs(tltlv->type))) {
			printf("\n\tInvalid ForCES Top TLV type=0x%x",
			       ntohs(tltlv->type));
			return -1;
		}

		if (vflag >= 3)
			printf("\t%s, length %d (data length %d Bytes)",
			       tok2str(ForCES_TLV, NULL, ntohs(tltlv->type)),
			       ntohs(tltlv->length), ntohs(tltlv->length) - 4);

		rc = tops->print((u_char *) TLV_DATA(tltlv),
				 ntohs(tltlv->length), tops->op_msk, 9);
		if (rc < 0) {
			return -1;
		}
		tltlv = GO_NXT_TLV(tltlv, tll);
		ttlv--;
		if (ttlv <= 0)
			break;
	}
	if (tll) {
		printf("\tMess TopTLV header: min %ld, total %d advertised %d ",
		       sizeof(struct forces_tlv), tll, ntohs(tltlv->length));
		return -1;
	}

	return 0;
}

void forces_print(register const u_char * pptr, register u_int len)
{
	const struct forcesh *fhdr;
	u_int16_t mlen;
	u_int32_t flg_raw;
	struct tom_h *tops;
	int rc = 0;

	fhdr = (const struct forcesh *)pptr;
	if (!tom_valid(fhdr->fm_tom)) {
		printf("Invalid ForCES message type %d\n", fhdr->fm_tom);
		goto error;
	}

	mlen = ForCES_BLN(fhdr);

	tops = get_forces_tom(fhdr->fm_tom);
	if (tops->v == TOM_RSVD) {
		printf("\n\tUnknown ForCES message type=0x%x", fhdr->fm_tom);
		goto error;
	}

	printf("\n\tForCES %s ", tops->s);
	if (!ForCES_HLN_VALID(mlen, len)) {
		printf
		    ("Illegal ForCES pkt len - min %ld, total recvd %d, advertised %d ",
		     sizeof(struct forcesh), len, ForCES_BLN(fhdr));
		goto error;
	}

	flg_raw = EXTRACT_32BITS(pptr + 20);
	if (vflag >= 1) {
		printf("\n\tForCES Version %d len %dB flags 0x%08x ",
		       ForCES_V(fhdr), mlen, flg_raw);
		printf("\n\tSrcID 0x%x(%s) DstID 0x%x(%s) Correlator 0x%"
		       PRIu64, ForCES_SID(fhdr), ForCES_node(ForCES_SID(fhdr)),
		       ForCES_DID(fhdr), ForCES_node(ForCES_DID(fhdr)),
		       EXTRACT_64BITS(fhdr->fm_cor));

	}
	if (vflag >= 2) {
		printf
		    ("\n\tForCES flags:\n\t  %s(0x%x), prio=%d, %s(0x%x),\n\t  %s(0x%x), %s(0x%x)\n",
		     ForCES_ACKp(fhdr->f_ack), fhdr->f_ack, fhdr->f_pri,
		     ForCES_EMp(fhdr->f_em), fhdr->f_em, ForCES_ATp(fhdr->f_at),
		     fhdr->f_at, ForCES_TPp(fhdr->f_tp), fhdr->f_tp);
		printf
		    ("\t  Extra flags: rsv(b5-7) 0x%x rsv(b13-15) 0x%x rsv(b16-31) 0x%x\n",
		     fhdr->f_rs1, fhdr->f_rs2, ntohs(fhdr->f_rs3));
	}
	rc = forces_type_print(pptr, fhdr, mlen, tops);
	if (rc < 0) {
error:
		hex_print_with_offset("\n\t[", pptr, len, 0);
		printf("\n\t]");
		return;
	}

	if (vflag >= 4) {
		printf("\n\t  Raw ForCES message \n\t [");
		hex_print_with_offset("\n\t ", pptr, len, 0);
		printf("\n\t ]");
	}
	printf("\n");
}
