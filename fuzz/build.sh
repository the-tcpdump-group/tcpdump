#!/bin/sh
#
# Use $OUT as a signal that we're being run inside the oss-fuzz
# build_fuzzers target.  See
# https://github.com/google/oss-fuzz/blob/master/docs/new_project_guide.md
# for the assumptions about the enviroment.
if [ -z "$OUT" ]
then
    echo "This script is only used when building the fuzz targets"
    echo "inside the oss-fuzz image."
    exit 1
fi

# First, the pcap fuzzer.
$CC $CFLAGS -I.. -I. -c ../fuzz/fuzz_pcap.c -o fuzz_pcap.o
$CXX $CXXFLAGS fuzz_pcap.o -o $OUT/fuzz_pcap libnetdissect.a \
    $SRC/libpcap/build/libpcap.a $LIB_FUZZING_ENGINE

zip -r fuzz_pcap_seed_corpus.zip ../tests/*.pcap
cp fuzz_pcap_seed_corpus.zip $OUT/

# Then, the individual per-printer fuzzers
$CC $CFLAGS -I.. -I. -c ../fuzz/common.c -o common.o

for p in ip ip6 ether bgp
do
    $CC $CFLAGS -I.. -I. -c ../fuzz/${p}_print_fuzzer.c -o ${p}_print_fuzzer.o
    $CXX $CXXFLAGS ${p}_print_fuzzer.o common.o -o $OUT/${p}_print_fuzzer \
        libnetdissect.a $SRC/libpcap/build/libpcap.a $LIB_FUZZING_ENGINE
done

# Build the per-printer corpus from the tests
cd $WORK
mkdir corpus
cd corpus
$SRC/tcpdump/fuzz/corpus/pcap2corpus $SRC/tcpdump/tests/*.pcap
for d in *
do
    zip -r $OUT/${d}_print_fuzzer_seed_corpus.zip $d/*
done

# Copy options
cp $SRC/tcpdump/fuzz/*.options $OUT/
