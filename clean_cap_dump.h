#ifndef clean_cap_dump_h
#define clean_cap_dump_h

#include <pcap/pcap.h>




/* CyberReboot edition:
 *
 * In new creating sanitization methods for tcpdump, it became necessary
 * to make modifications to pcap_dump() supplied by pcap/sf-pcap -- and in
 * so doing, required an awareness of internal structs located in the
 * pcap-int.h (a component of libpcap). To simplify things, required data
 * structs have been extrapolated and given new names to avoid conflict,
 * and while these are completely extricated from libpcap's internal
 * structure, data types and sizes should be identical (as they've been
 * shamelessly cut-and-pasted from pcap-int.h).
 *
 */

/*
 * This is a timeval as stored in a savefile.
 * It has to use the same types everywhere, independent of the actual
 * `struct timeval'; `struct timeval' has 32-bit tv_sec values on some
 * platforms and 64-bit tv_sec values on other platforms, and writing
 * out native `struct timeval' values would mean files could only be
 * read on systems with the same tv_sec size as the system on which
 * the file was written.
 */
struct clean_cap_timeval {
	int tv_sec;	/* seconds */
	int tv_usec;	/* microseconds */
} clean_cap_timeval;

struct clean_cap_sf_pkthdr {
	struct clean_cap_timeval ts;	/* time stamp */
	bpf_u_int32 caplen;	   	/* length of portion present */
	bpf_u_int32 len;		/* length this packet (off wire) */
} clean_cap_sf_pkthdr;

struct netblock {
	uint32_t netip;
	uint32_t netmask;
} netblock;

/* Takes over the packet mods and pcap_dump when the new flags are called */
void pcap_mod_and_dump(u_char *, const struct pcap_pkthdr *, const u_char *,
                  int, int, int, const char *);

u_char * get_iph_ptr(const struct pcap_pkthdr *, u_char *);
int mask_ip(u_char *, unsigned int, const char *);


#endif
