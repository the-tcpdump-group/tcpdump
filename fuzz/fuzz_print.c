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


int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    int r;
    struct pcap_pkthdr header;
    netdissect_options Ndo;

    if (Size < 1) {
        //DLT on first byte
        return 0;
    }
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

    if_printer_t printer;
    printer = lookup_printer(&Ndo, Data[0]);
    if (printer.printer == NULL) {
        //do not go further if we have no printer
        return 0;
    }
    Ndo.ndo_if_printer = get_if_printer(&Ndo, Data[0]);

    header.len = Size-1;
    header.caplen = Size-1;
    pretty_print_packet(&Ndo, &header, Data+1, 0);

    return 0;
}
