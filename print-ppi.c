/*
 * Oracle
 */

/* \summary: Oracle DLT_PPI printer */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include "netdissect.h"
#include "extract.h"


typedef struct ppi_header {
	nd_uint8_t	ppi_ver;
	nd_uint8_t	ppi_flags;
	nd_uint16_t	ppi_len;
	nd_uint32_t	ppi_dlt;
} ppi_header_t;

#define	PPI_HDRLEN	8

#ifdef DLT_PPI

static void
ppi_header_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
	const ppi_header_t *hdr;
	uint16_t len;
	uint32_t dlt;
	const char *dltname;

	hdr = (const ppi_header_t *)bp;

	len = EXTRACT_LE_U_2(hdr->ppi_len);
	dlt = EXTRACT_LE_U_4(hdr->ppi_dlt);
	dltname = pcap_datalink_val_to_name(dlt);

	if (!ndo->ndo_qflag) {
		ND_PRINT("V.%u DLT %s (%u) len %u", EXTRACT_U_1(hdr->ppi_ver),
			  (dltname != NULL ? dltname : "UNKNOWN"), dlt,
                          len);
        } else {
		ND_PRINT("%s", (dltname != NULL ? dltname : "UNKNOWN"));
        }

	ND_PRINT(", length %u: ", length);
}

static u_int
ppi_print(netdissect_options *ndo,
	  const struct pcap_pkthdr *h, const u_char *p)
{
	if_printer printer;
	const ppi_header_t *hdr;
	u_int caplen = h->caplen;
	u_int length = h->len;
	uint16_t len;
	uint32_t dlt;
	uint32_t hdrlen;
	struct pcap_pkthdr nhdr;

	ndo->ndo_protocol = "ppi";
	if (caplen < sizeof(ppi_header_t)) {
		nd_print_trunc(ndo);
		return (caplen);
	}

	hdr = (const ppi_header_t *)p;
	ND_TCHECK_2(hdr->ppi_len);
	len = EXTRACT_LE_U_2(hdr->ppi_len);
	if (caplen < len) {
		/*
		 * If we don't have the entire PPI header, don't
		 * bother.
		 */
		nd_print_trunc(ndo);
		return (caplen);
	}
	if (len < sizeof(ppi_header_t)) {
		nd_print_trunc(ndo);
		return (len);
	}
	ND_TCHECK_4(hdr->ppi_dlt);
	dlt = EXTRACT_LE_U_4(hdr->ppi_dlt);

	if (ndo->ndo_eflag)
		ppi_header_print(ndo, p, length);

	length -= len;
	caplen -= len;
	p += len;

	if ((printer = lookup_printer(dlt)) != NULL) {
		nhdr = *h;
		nhdr.caplen = caplen;
		nhdr.len = length;
		hdrlen = printer(ndo, &nhdr, p);
	} else {
		if (!ndo->ndo_eflag)
			ppi_header_print(ndo, (const u_char *)hdr, length + len);

		if (!ndo->ndo_suppress_default_print)
			ND_DEFAULTPRINT(p, caplen);
		hdrlen = 0;
	}
	return (len + hdrlen);
trunc:
	return (caplen);
}

/*
 * This is the top level routine of the printer.  'p' points
 * to the ether header of the packet, 'h->ts' is the timestamp,
 * 'h->len' is the length of the packet off the wire, and 'h->caplen'
 * is the number of bytes actually captured.
 */
u_int
ppi_if_print(netdissect_options *ndo,
	     const struct pcap_pkthdr *h, const u_char *p)
{
	ndo->ndo_protocol = "ppi_if";
	return (ppi_print(ndo, h, p));
}
#endif /* DLT_PPI */
