#include <config.h>
#include "netdissect-stdinc.h"
#include <sys/stat.h>

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
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

void fuzz_openFile(const char * name) {
    if (outfile != NULL) {
        fclose(outfile);
    }
    outfile = fopen(name, "w");
}

static int bufferToFile(const char * name, const uint8_t *Data, size_t Size) {
    FILE * fd;
    if (remove(name) != 0) {
        if (errno != ENOENT) {
            printf("failed remove, errno=%d\n", errno);
            return -1;
        }
    }
    fd = fopen(name, "wb");
    if (fd == NULL) {
        printf("failed open, errno=%d\n", errno);
        return -2;
    }
    if (fwrite (Data, 1, Size, fd) != Size) {
        fclose(fd);
        return -3;
    }
    fclose(fd);
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    pcap_t * pkts;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char *pkt;
    struct pcap_pkthdr *header;
    int r;
    u_int packets_captured = 0;
    netdissect_options Ndo;

    //initialize output file
    if (outfile == NULL) {
        outfile = fopen("/dev/null", "w");
        if (outfile == NULL) {
            return 0;
        }
    }

    memset(&Ndo, 0, sizeof(Ndo));
    ndo_set_function_pointers(&Ndo);
    Ndo.program_name = "fuzz";
    //avoid lookups
    Ndo.ndo_nflag = 1;
    //most verbose
    Ndo.ndo_vflag = 5;
    //to out outputfile
    Ndo.ndo_printf=fuzz_ndo_printf;
    init_print(&Ndo, 0, 0);

    //rewrite buffer to a file as libpcap does not have buffer inputs
    if (bufferToFile("/tmp/fuzz.pcap", Data, Size) < 0) {
        return 0;
    }

    //initialize structure
    pkts = pcap_open_offline("/tmp/fuzz.pcap", errbuf);
    if (pkts == NULL) {
        fprintf(outfile, "Couldn't open pcap file %s\n", errbuf);
        return 0;
    }
    if_printer_t printer;
    printer = lookup_printer(&Ndo, pcap_datalink(pkts));
    if (printer.printer == NULL) {
        //do not go further if we have no printer
        pcap_close(pkts);
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
