#include <config.h>
#include "netdissect-stdinc.h"
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <pcap/pcap.h>
#include "netdissect.h"
#include "print.h"

FILE * outfile = NULL;

static int
fuzz_ndo_printf(netdissect_options *ndo, const char *fmt, ...)
{
    va_list args;
    int ret;

    va_start(args, fmt);
    ret = vfprintf(outfile, fmt, args);
    va_end(args);

    return (ret);
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    pcap_t * pkts;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *pkt;
    struct pcap_pkthdr *header;
    int r;
    u_int packets_captured = 0;
    netdissect_options Ndo;

    memset(&Ndo, 0, sizeof(Ndo));
    ndo_set_function_pointers(&Ndo);
    Ndo.program_name = "fuzz";
    //avoid lookups
    Ndo.ndo_nflag = 1;
    //most verbose
    Ndo.ndo_vflag = 5;
    //to out outputfile
    Ndo.ndo_printf=fuzz_ndo_printf;

    //initialize output file
    if (outfile == NULL) {
        outfile = fopen("/dev/null", "w");
        if (outfile == NULL) {
            return 0;
        }
        init_print(&Ndo, 0, 0);
    }

    //rewrite buffer to a file as libpcap does not have buffer inputs
    int fd = open("/tmp/fuzz.pcap", O_RDWR | O_CREAT, 0666);
    if (fd == -1) {
        printf("failed open, errno=%d\n", errno);
        return 0;
    }
    if (ftruncate(fd, Size) == -1) {
        return 0;
    }
    if (lseek (fd, 0, SEEK_SET) < 0) {
        return 0;
    }
    if (write (fd, Data, Size) != Size) {
        return 0;
    }
    close(fd);

    //initialize structure
    pkts = pcap_open_offline("/tmp/fuzz.pcap", errbuf);
    if (pkts == NULL) {
        fprintf(outfile, "Couldn't open pcap file %s\n", errbuf);
        return 0;
    }
    Ndo.ndo_if_printer = get_if_printer(&Ndo, pcap_datalink(pkts));

    //loop over packets
    r = pcap_next_ex(pkts, &header, &pkt);
    while (r > 0) {
        packets_captured++;
        pretty_print_packet(&Ndo, header, pkt, packets_captured);
        r = pcap_next_ex(pkts, &header, &pkt);
    }
    //close structure
    pcap_close(pkts);

    return 0;
}
