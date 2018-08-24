add_executable(fuzz_pcap onefile.c fuzz_pcap.c)
target_link_libraries(fuzz_pcap netdissect ${TCPDUMP_LINK_LIBRARIES})
