/*
 * Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 2000
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Support for splitting captures into multiple files with a maximum
 * file size:
 *
 * Copyright (c) 2001
 *	Seth Webster <swebster@sst.ll.mit.edu>
 */

#ifndef lint
static const char copyright[] =
    "@(#) Copyright (c) 1988, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 2000\n\
The Regents of the University of California.  All rights reserved.\n";
static const char rcsid[] =
    "@(#) $Header: /tcpdump/master/tcpdump/tcpdump.c,v 1.197 2003-01-07 09:51:20 hannes Exp $ (LBL)";
#endif

/*
 * tcpdump - monitor tcp/ip traffic on an ethernet.
 *
 * First written in 1987 by Van Jacobson, Lawrence Berkeley Laboratory.
 * Mercilessly hacked and occasionally improved since then via the
 * combined efforts of Van, Steve McCanne and Craig Leres of LBL.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <tcpdump-stdinc.h>

#ifdef WIN32
#include "getopt.h"
#include "w32_fzs.h"
extern int strcasecmp (const char *__s1, const char *__s2);
extern int SIZE_BUF;
#define off_t long
#define uint UINT
#endif /* WIN32 */

#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "interface.h"
#include "addrtoname.h"
#include "machdep.h"
#include "setsignal.h"
#include "gmt2local.h"
#include "pcap-missing.h"

int aflag;			/* translate network and broadcast addresses */
int dflag;			/* print filter code */
int eflag;			/* print ethernet header */
int fflag;			/* don't translate "foreign" IP address */
int Lflag;			/* list available data link types and exit */
int nflag;			/* leave addresses as numbers */
int Nflag;			/* remove domains from printed host names */
int Oflag = 1;			/* run filter code optimizer */
int pflag;			/* don't go promiscuous */
int qflag;			/* quick (shorter) output */
int Rflag = 1;			/* print sequence # field in AH/ESP*/
int sflag = 0;			/* use the libsmi to translate OIDs */
int Sflag;			/* print raw TCP sequence numbers */
int tflag = 1;			/* print packet arrival time */
int Uflag = 0;			/* "unbuffered" output of dump files */
int uflag = 0;			/* Print undecoded NFS handles */
int vflag;			/* verbose */
int xflag;			/* print packet in hex */
int Xflag;			/* print packet in ascii as well as hex */
off_t Cflag = 0;                /* rotate dump files after this many bytes */
int Aflag = 0;                  /* print packet only in ascii observing LF, CR, TAB, SPACE */
int dlt = -1;		/* if != -1, ask libpcap for the DLT it names */

const char *dlt_name = NULL;

char *espsecret = NULL;		/* ESP secret key */

int packettype;

static int infodelay;
static int infoprint;

char *program_name;

int32_t thiszone;		/* seconds offset from gmt to local time */

/* Forwards */
static RETSIGTYPE cleanup(int);
static void usage(void) __attribute__((noreturn));
static void show_dlts_and_exit(pcap_t *pd) __attribute__((noreturn));

static void print_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
static void dump_packet_and_trunc(u_char *, const struct pcap_pkthdr *, const u_char *);
static void dump_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

#ifdef SIGINFO
RETSIGTYPE requestinfo(int);
#endif

static void info(int);

/* Length of saved portion of packet. */
int snaplen = DEFAULT_SNAPLEN;

typedef u_int (*if_printer)(const struct pcap_pkthdr *, const u_char *);

struct printer {
	if_printer f;
	int type;
};

static struct printer printers[] = {
	{ arcnet_if_print,	DLT_ARCNET },
	{ ether_if_print,	DLT_EN10MB },
	{ token_if_print,	DLT_IEEE802 },
#ifdef DLT_LANE8023
	{ lane_if_print,        DLT_LANE8023 },
#endif
#ifdef DLT_CIP
	{ cip_if_print,         DLT_CIP },
#endif
#ifdef DLT_ATM_CLIP
	{ cip_if_print,         DLT_ATM_CLIP },
#endif
	{ sl_if_print,		DLT_SLIP },
	{ sl_bsdos_if_print,	DLT_SLIP_BSDOS },
	{ ppp_if_print,		DLT_PPP },
	{ ppp_bsdos_if_print,	DLT_PPP_BSDOS },
	{ fddi_if_print,	DLT_FDDI },
	{ null_if_print,	DLT_NULL },
#ifdef DLT_LOOP
	{ null_if_print,	DLT_LOOP },
#endif
	{ raw_if_print,		DLT_RAW },
	{ atm_if_print,		DLT_ATM_RFC1483 },
#ifdef DLT_C_HDLC
	{ chdlc_if_print,	DLT_C_HDLC },
#endif
#ifdef DLT_HDLC
	{ chdlc_if_print,	DLT_HDLC },
#endif
#ifdef DLT_PPP_SERIAL
	{ ppp_hdlc_if_print,    DLT_PPP_SERIAL },
#endif
#ifdef DLT_PPP_ETHER
	{ pppoe_if_print,	DLT_PPP_ETHER },
#endif
#ifdef DLT_LINUX_SLL
	{ sll_if_print,		DLT_LINUX_SLL },
#endif
#ifdef DLT_IEEE802_11
	{ ieee802_11_if_print,	DLT_IEEE802_11},
#endif
#ifdef DLT_LTALK
	{ ltalk_if_print,	DLT_LTALK },
#endif
#ifdef DLT_PFLOG
	{ pflog_if_print, 	DLT_PFLOG },
#endif
#ifdef DLT_FR
	{ fr_if_print,		DLT_FR },
#endif
#ifdef DLT_FRELAY
	{ fr_if_print,		DLT_FRELAY },
#endif
#ifdef DLT_SUNATM
	{ sunatm_if_print,	DLT_SUNATM },
#endif
#ifdef DLT_IP_OVER_FC
	{ ipfc_if_print,	DLT_IP_OVER_FC },
#endif
#ifdef DLT_PRISM_HEADER
	{ prism_if_print,	DLT_PRISM_HEADER },
#endif
#ifdef DLT_IEEE802_11_RADIO
	{ ieee802_11_radio_if_print,	DLT_IEEE802_11_RADIO },
#endif
	{ NULL,			0 },
};

static if_printer
lookup_printer(int type)
{
	struct printer *p;

	for (p = printers; p->f; ++p)
		if (type == p->type)
			return p->f;

	return NULL;
	/* NOTREACHED */
}

static pcap_t *pd;

extern int optind;
extern int opterr;
extern char *optarg;

struct print_info {
	if_printer printer;
};

struct dump_info {
	char	*WFileName;
	pcap_t	*pd;
	pcap_dumper_t *p;
};

static void
show_dlts_and_exit(pcap_t *pd)
{
	int n_dlts;
	int *dlts = 0;
	const char *dlt_name;

	n_dlts = pcap_list_datalinks(pd, &dlts);
	if (n_dlts < 0)
		error("%s", pcap_geterr(pd));
	else if (n_dlts == 0 || !dlts)
		error("No data link types.");

	(void) fprintf(stderr, "Data link types (use option -y to set):\n");

	while (--n_dlts >= 0) {
		dlt_name = pcap_datalink_val_to_name(dlts[n_dlts]);
		if (dlt_name != NULL) {
			(void) fprintf(stderr, "  %s", dlt_name);

			/*
			 * OK, does tcpdump handle that type?
			 */
			if (lookup_printer(dlts[n_dlts]) == NULL)
				(void) fprintf(stderr, " (not supported)");
			putchar('\n');
		} else {
			(void) fprintf(stderr, "  DLT %d (not supported)\n",
			    dlts[n_dlts]);
		}
	}
	free(dlts);
	exit(0);
}

/*
 * Set up flags that might or might not be supported depending on the
 * version of libpcap we're using.
 */
#ifdef WIN32
#define B_FLAG		"B:"
#define B_FLAG_USAGE	" [ -B size ]"
#else /* WIN32 */
#define B_FLAG
#define B_FLAG_USAGE
#endif /* WIN32 */

#ifdef HAVE_PCAP_FINDALLDEVS
#define D_FLAG	"D"
#else
#define D_FLAG
#endif

#ifdef HAVE_PCAP_DUMP_FLUSH
#define U_FLAG	"U"
#else
#define U_FLAG
#endif

int
main(int argc, char **argv)
{
	register int cnt, op, i;
	bpf_u_int32 localnet, netmask;
	register char *cp, *infile, *cmdbuf, *device, *RFileName, *WFileName;
	pcap_handler callback;
	int type;
	struct bpf_program fcode;
#ifndef WIN32
	RETSIGTYPE (*oldhandler)(int);
#endif
	struct print_info printinfo;
	struct dump_info dumpinfo;
	u_char *pcap_userdata;
	char ebuf[PCAP_ERRBUF_SIZE];
#ifdef HAVE_PCAP_FINDALLDEVS
	pcap_if_t *devpointer;
	int devnum;
#endif
#ifdef WIN32
	DWORD dwVersion;
	DWORD dwWindowsMajorVersion;
	u_int UserBufferSize=1000000;
#endif

#ifdef WIN32
	dwVersion=GetVersion();		/* get the OS version */
	dwWindowsMajorVersion =  (DWORD)(LOBYTE(LOWORD(dwVersion)));
	if(wsockinit()!=0) return 1;
#endif /* WIN32 */

	cnt = -1;
	device = NULL;
	infile = NULL;
	RFileName = NULL;
	WFileName = NULL;
	if ((cp = strrchr(argv[0], '/')) != NULL)
		program_name = cp + 1;
	else
		program_name = argv[0];

	if (abort_on_misalignment(ebuf, sizeof(ebuf)) < 0)
		error("%s", ebuf);

#ifdef LIBSMI
	smiInit("tcpdump");
#endif

	opterr = 0;
	while (
	    (op = getopt(argc, argv, "aA" B_FLAG "c:C:d" D_FLAG "eE:fF:i:lLm:nNOpqr:Rs:StT:u" U_FLAG "vw:xXy:Y")) != -1)
		switch (op) {

		case 'a':
			++aflag;
			break;

		case 'A':
			++xflag;
			++Xflag;
			++Aflag;
			break;

#ifdef WIN32
		case 'B':
			UserBufferSize = atoi(optarg)*1024;
			if (UserBufferSize < 0)
				error("invalid packet buffer size %s", optarg);
			break;
#endif /* WIN32 */

		case 'c':
			cnt = atoi(optarg);
			if (cnt <= 0)
				error("invalid packet count %s", optarg);
			break;

		case 'C':
			Cflag = atoi(optarg) * 1000000;
			if (Cflag < 0)
				error("invalid file size %s", optarg);
			break;

		case 'd':
			++dflag;
			break;

#ifdef HAVE_PCAP_FINDALLDEVS
		case 'D':
			if (pcap_findalldevs(&devpointer, ebuf) < 0)
				error("%s", ebuf);
			else {
				for (i = 0; devpointer != 0; i++) {
					printf("%d.%s", i+1, devpointer->name);
					if (devpointer->description != NULL)
						printf(" (%s)", devpointer->description);
					printf("\n");
					devpointer = devpointer->next;
				}
			}
			return 0;
#endif /* HAVE_PCAP_FINDALLDEVS */

		case 'L':
			Lflag++;
			break;

		case 'e':
			++eflag;
			break;

		case 'E':
#ifndef HAVE_LIBCRYPTO
			warning("crypto code not compiled in");
#endif
			espsecret = optarg;
			break;

		case 'f':
			++fflag;
			break;

		case 'F':
			infile = optarg;
			break;

		case 'i':
			if (optarg[0] == '0' && optarg[1] == 0)
				error("Invalid adapter index");
			
#ifdef HAVE_PCAP_FINDALLDEVS
			/*
			 * If the argument is a number, treat it as
			 * an index into the list of adapters, as
			 * printed by "tcpdump -D".
			 *
			 * This should be OK on UNIX systems, as interfaces
			 * shouldn't have names that begin with digits.
			 * It can be useful on Windows, where more than
			 * one interface can have the same name.
			 */
			if ((devnum = atoi(optarg)) != 0) {
				if (devnum < 0)
					error("Invalid adapter index");

				if (pcap_findalldevs(&devpointer, ebuf) < 0)
					error("%s", ebuf);
				else {
					for (i = 0; i < devnum-1; i++){
						devpointer = devpointer->next;
						if (devpointer == NULL)
							error("Invalid adapter index");
					}
				}
				device = devpointer->name;
				break;
			}
#endif /* HAVE_PCAP_FINDALLDEVS */
			device = optarg;
			break;

		case 'l':
#ifdef HAVE_SETLINEBUF
			setlinebuf(stdout);
#else
			setvbuf(stdout, NULL, _IOLBF, 0);
#endif
			break;

		case 'n':
			++nflag;
			break;

		case 'N':
			++Nflag;
			break;

		case 'm':
#ifdef LIBSMI
		        if (smiLoadModule(optarg) == 0) {
				error("could not load MIB module %s", optarg);
		        }
			sflag = 1;
#else
			(void)fprintf(stderr, "%s: ignoring option `-m %s' ",
				      program_name, optarg);
			(void)fprintf(stderr, "(no libsmi support)\n");
#endif

		case 'O':
			Oflag = 0;
			break;

		case 'p':
			++pflag;
			break;

		case 'q':
			++qflag;
			break;

		case 'r':
			RFileName = optarg;
			break;

		case 'R':
			Rflag = 0;
			break;

		case 's': {
			char *end;

			snaplen = strtol(optarg, &end, 0);
			if (optarg == end || *end != '\0'
			    || snaplen < 0 || snaplen > 65535)
				error("invalid snaplen %s", optarg);
			else if (snaplen == 0)
				snaplen = 65535;
			break;
		}

		case 'S':
			++Sflag;
			break;

		case 't':
			--tflag;
			break;

		case 'T':
			if (strcasecmp(optarg, "vat") == 0)
				packettype = PT_VAT;
			else if (strcasecmp(optarg, "wb") == 0)
				packettype = PT_WB;
			else if (strcasecmp(optarg, "rpc") == 0)
				packettype = PT_RPC;
			else if (strcasecmp(optarg, "rtp") == 0)
				packettype = PT_RTP;
			else if (strcasecmp(optarg, "rtcp") == 0)
				packettype = PT_RTCP;
			else if (strcasecmp(optarg, "snmp") == 0)
				packettype = PT_SNMP;
			else if (strcasecmp(optarg, "cnfp") == 0)
				packettype = PT_CNFP;
			else
				error("unknown packet type `%s'", optarg);
			break;

		case 'u':
			++uflag;
			break;

#ifdef HAVE_PCAP_DUMP_FLUSH
		case 'U':
			++Uflag;
			break;
#endif

		case 'v':
			++vflag;
			break;

		case 'w':
			WFileName = optarg;
			break;

		case 'x':
			++xflag;
			break;

		case 'X':
		        ++xflag;
			++Xflag;
			break;

		case 'y':
			dlt_name = optarg;
			dlt = pcap_datalink_name_to_val(dlt_name);
			if (dlt < 0)
				error("invalid data link type %s", dlt_name);
			break;

#if defined(HAVE_PCAP_DEBUG) || defined(HAVE_YYDEBUG)
		case 'Y':
			{
			/* Undocumented flag */
#ifdef HAVE_PCAP_DEBUG
			extern int pcap_debug;
			pcap_debug = 1;
#else
			extern int yydebug;
			yydebug = 1;
#endif
			}
			break;
#endif
		default:
			usage();
			/* NOTREACHED */
		}

	if (aflag && nflag)
		error("-a and -n options are incompatible");

	if (tflag > 0)
		thiszone = gmt2local(0);

	if (RFileName != NULL) {
		/*
		 * We don't need network access, so set it back to the user id.
		 * Also, this prevents the user from reading anyone's
		 * trace file.
		 */
#ifndef WIN32
		setuid(getuid());
#endif /* WIN32 */

		pd = pcap_open_offline(RFileName, ebuf);
		if (pd == NULL)
			error("%s", ebuf);
		localnet = 0;
		netmask = 0;
		if (fflag != 0)
			error("-f and -r options are incompatible");
	} else {
		if (device == NULL) {
			device = pcap_lookupdev(ebuf);
			if (device == NULL)
				error("%s", ebuf);
		}
#ifdef WIN32
		PrintCapBegins(program_name,device);
#endif /* WIN32 */
		*ebuf = '\0';
		pd = pcap_open_live(device, snaplen, !pflag, 1000, ebuf);
		if (pd == NULL)
			error("%s", ebuf);
		else if (*ebuf)
			warning("%s", ebuf);
#ifdef WIN32
		if(UserBufferSize != 1000000)
			if(pcap_setbuff(pd, UserBufferSize)==-1){
				error("%s", pcap_geterr(pd));
			}
#endif /* WIN32 */
		if (Lflag)
			show_dlts_and_exit(pd);
		if (dlt >= 0) {
#ifdef HAVE_PCAP_SET_DATALINK
			if (pcap_set_datalink(pd, dlt) < 0)
				error("%s", pcap_geterr(pd));
#else
			/*
			 * We don't actually support changing the
			 * data link type, so we only let them
			 * set it to what it already is.
			 */
			if (dlt != pcap_datalink(pd)) {
				error("%s is not one of the DLTs supported by this device\n",
				    dlt_name);
			}
#endif
			(void)fprintf(stderr, "%s: data link type %s\n",
			              program_name, dlt_name);
			(void)fflush(stderr);
		}
		i = pcap_snapshot(pd);
		if (snaplen < i) {
			warning("snaplen raised from %d to %d", snaplen, i);
			snaplen = i;
		}
		if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0) {
			localnet = 0;
			netmask = 0;
			warning("%s", ebuf);
		}
		/*
		 * Let user own process after socket has been opened.
		 */
#ifndef WIN32
		setuid(getuid());
#endif /* WIN32 */
	}
	if (infile)
		cmdbuf = read_infile(infile);
	else
		cmdbuf = copy_argv(&argv[optind]);

	if (pcap_compile(pd, &fcode, cmdbuf, Oflag, netmask) < 0)
		error("%s", pcap_geterr(pd));
	if (dflag) {
		bpf_dump(&fcode, dflag);
		pcap_close(pd);
		exit(0);
	}
	init_addrtoname(localnet, netmask);

	(void)setsignal(SIGTERM, cleanup);
	(void)setsignal(SIGINT, cleanup);
	/* Cooperate with nohup(1) */
#ifndef WIN32	
	if ((oldhandler = setsignal(SIGHUP, cleanup)) != SIG_DFL)
		(void)setsignal(SIGHUP, oldhandler);
#endif /* WIN32 */

	if (pcap_setfilter(pd, &fcode) < 0)
		error("%s", pcap_geterr(pd));
	if (WFileName) {
		pcap_dumper_t *p = pcap_dump_open(pd, WFileName);
		if (p == NULL)
			error("%s", pcap_geterr(pd));
		if (Cflag != 0) {
			callback = dump_packet_and_trunc;
			dumpinfo.WFileName = WFileName;
			dumpinfo.pd = pd;
			dumpinfo.p = p;
			pcap_userdata = (u_char *)&dumpinfo;
		} else {
			callback = dump_packet;
			pcap_userdata = (u_char *)p;
		}
	} else {
		type = pcap_datalink(pd);
		printinfo.printer = lookup_printer(type);
		if (printinfo.printer == NULL) {
			dlt_name = pcap_datalink_val_to_name(type);
			if (dlt_name != NULL)
				error("unsupported data link type %s", dlt_name);
			else
				error("unsupported data link type %d", type);
		}
		callback = print_packet;
		pcap_userdata = (u_char *)&printinfo;
	}
#ifdef SIGINFO
	(void)setsignal(SIGINFO, requestinfo);
#endif
#ifndef WIN32
	if (RFileName == NULL) {
            if (vflag == 0)
                (void)fprintf(stderr, "%s: verbose output suppressed, use -v or -vv for full protocol decode\n",program_name);
            (void)fprintf(stderr, "listening on %s, capture size %u bytes\n", device, snaplen);
            (void)fflush(stderr);
	}
#endif /* WIN32 */
	if (pcap_loop(pd, cnt, callback, pcap_userdata) < 0) {
		(void)fprintf(stderr, "%s: pcap_loop: %s\n",
		    program_name, pcap_geterr(pd));
		cleanup(0);
		pcap_close(pd);
		exit(1);
	}
	if (RFileName == NULL)
		info(1);
	pcap_close(pd);
	exit(0);
}

/* make a clean exit on interrupts */
static RETSIGTYPE
cleanup(int signo)
{

	/* Can't print the summary if reading from a savefile */
	if (pd != NULL && pcap_file(pd) == NULL) {
		(void)fflush(stdout);
		putc('\n', stderr);
		info(1);
	}
	if (signo)
		exit(0);
}

static void
info(register int verbose)
{
	struct pcap_stat stat;

	if (pcap_stats(pd, &stat) < 0) {
		(void)fprintf(stderr, "pcap_stats: %s\n", pcap_geterr(pd));
		return;
	}

	if (!verbose)
		fprintf(stderr, "%s: ", program_name);

	(void)fprintf(stderr, "%d packets received by filter", stat.ps_recv);
	if (!verbose)
		fputs(", ", stderr);
	else
		putc('\n', stderr);
	(void)fprintf(stderr, "%d packets dropped by kernel\n", stat.ps_drop);
	infoprint = 0;
}

static void
reverse(char *s)
{
	int i, j, c;

	for (i = 0, j = strlen(s) - 1; i < j; i++, j--) {
		c = s[i];
		s[i] = s[j];
		s[j] = c;
	}
}


static void
swebitoa(unsigned int n, char *s)
{
	unsigned int i;

	i = 0;
	do {
		s[i++] = n % 10 + '0';
	} while ((n /= 10) > 0);

	s[i] = '\0';
	reverse(s);
}

static void
dump_packet_and_trunc(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
	struct dump_info *dump_info;
	static uint cnt = 2;
	char *name;

	++infodelay;

	dump_info = (struct dump_info *)user;

	/*
	 * XXX - this won't prevent capture files from getting
	 * larger than Cflag - the last packet written to the
	 * file could put it over Cflag.
	 */
	if (ftell((FILE *)dump_info->p) > Cflag) {
		name = (char *) malloc(strlen(dump_info->WFileName) + 4);
		if (name == NULL)
			error("dump_packet_and_trunc: malloc");
		strcpy(name, dump_info->WFileName);
		swebitoa(cnt, name + strlen(dump_info->WFileName));
		cnt++;
		pcap_dump_close(dump_info->p);
		dump_info->p = pcap_dump_open(dump_info->pd, name);
		free(name);
		if (dump_info->p == NULL)
			error("%s", pcap_geterr(pd));
	}

	pcap_dump((u_char *)dump_info->p, h, sp);
#ifdef HAVE_PCAP_DUMP_FLUSH
	if (Uflag)
		pcap_dump_flush(dump_info->p);
#endif

	--infodelay;
	if (infoprint)
		info(0);
}

static void
dump_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
	++infodelay;

	pcap_dump(user, h, sp);
#ifdef HAVE_PCAP_DUMP_FLUSH
	if (Uflag)
		pcap_dump_flush((pcap_dumper_t *)user);
#endif

	--infodelay;
	if (infoprint)
		info(0);
}

static void
print_packet(u_char *user, const struct pcap_pkthdr *h, const u_char *sp)
{
	struct print_info *print_info;
	u_int hdrlen;

	++infodelay;
	ts_print(&h->ts);

	print_info = (struct print_info *)user;

	/*
	 * Some printers want to check that they're not walking off the
	 * end of the packet.
	 * Rather than pass it all the way down, we set this global.
	 */
	snapend = sp + h->caplen;

	hdrlen = (*print_info->printer)(h, sp);
	if (xflag) {
		/*
		 * Print the raw packet data.
		 */
		if (xflag > 1) {
			/*
			 * Include the link-layer header.
			 */
			default_print_unaligned(sp, h->caplen);
		} else {
			/*
			 * Don't include the link-layer header - and if
			 * we have nothing past the link-layer header,
			 * print nothing.
			 */
			if (h->caplen > hdrlen)
				default_print_unaligned(sp + hdrlen,
				    h->caplen - hdrlen);
		}
	}

	putchar('\n');

	--infodelay;
	if (infoprint)
		info(0);
}

/* Like default_print() but data need not be aligned */
void
default_print_unaligned(register const u_char *cp, register u_int length)
{
	register u_int i, s;
	register int nshorts;

	if (Xflag) {
		ascii_print(cp, length);
		return;
	}
	nshorts = (u_int) length / sizeof(u_short);
	i = 0;
	while (--nshorts >= 0) {
		if ((i++ % 8) == 0)
			(void)printf("\n\t\t\t");
		s = *cp++;
		(void)printf(" %02x%02x", s, *cp++);
	}
	if (length & 1) {
		if ((i % 8) == 0)
			(void)printf("\n\t\t\t");
		(void)printf(" %02x", *cp);
	}
}

#ifdef WIN32
	/*
	 * XXX - there should really be libpcap calls to get the version
	 * number as a string (the string would be generated from #defines
	 * at run time, so that it's not generated from string constants
	 * in the library, as, on many UNIX systems, those constants would
	 * be statically linked into the application executable image, and
	 * would thus reflect the version of libpcap on the system on
	 * which the application was *linked*, not the system on which it's
	 * *running*.
	 *
	 * That routine should be documented, unlike the "version[]"
	 * string, so that UNIX vendors providing their own libpcaps
	 * don't omit it (as a couple of vendors have...).
	 *
	 * Packet.dll should perhaps also export a routine to return the
	 * version number of the Packet.dll code, to supply the
	 * "Wpcap_version" information on Windows.
	 */
	char WDversion[]="current-cvs.tcpdump.org";
	char version[]="current-cvs.tcpdump.org";
	char pcap_version[]="current-cvs.tcpdump.org";
	char Wpcap_version[]="3.0 alpha";
#endif

/*
 * By default, print the specified data out in hex.
 */
void
default_print(register const u_char *bp, register u_int length)
{
	default_print_unaligned(bp, length);
}

#ifdef SIGINFO
RETSIGTYPE requestinfo(int signo _U_)
{
	if (infodelay)
		++infoprint;
	else
		info(0);
}
#endif

static void
usage(void)
{
	extern char version[];
#if defined(WIN32) || defined(HAVE_PCAP_VERSION)
	extern char pcap_version[];
#else
	static char pcap_version[] = "unknown";
#endif

#ifdef WIN32
	(void)fprintf(stderr, "%s version %s, based on tcpdump version %s\n", program_name, WDversion, version);
	(void)fprintf(stderr, "WinPcap version %s, based on libpcap version %s\n",Wpcap_version, pcap_version);
#else	
	(void)fprintf(stderr, "%s version %s\n", program_name, version);
	(void)fprintf(stderr, "libpcap version %s\n", pcap_version);
#endif /* WIN32 */
	(void)fprintf(stderr,
"Usage: %s [-aAd" D_FLAG "eflLnNOpqRStu" U_FLAG "vxXy]" B_FLAG_USAGE " [-c count] [ -C file_size ]\n", program_name);
	(void)fprintf(stderr,
"\t\t[ -E algo:secret ] [ -F file ] [ -i interface ] [ -r file ]\n");
	(void)fprintf(stderr,
"\t\t[ -s snaplen ] [ -T type ] [ -w file ] [ -y datalinktype ]\n");
	(void)fprintf(stderr,
"\t\t[ expression ]\n");
	exit(1);
}
