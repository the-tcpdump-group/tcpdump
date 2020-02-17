set(fuzz_pcap_src fuzz_pcap.c)
set(fuzz_pcap_libs netdissect ${TCPDUMP_LINK_LIBRARIES})

IF(DEFINED ENV{LIB_FUZZING_ENGINE})
	set(fuzz_pcap_libs ${fuzz_pcap_libs} $ENV{LIB_FUZZING_ENGINE})
else()
	set(fuzz_pcap_src ${fuzz_pcap_src} onefile.c)
endif()

add_executable(fuzz_pcap ${fuzz_pcap_src})
set_target_properties(fuzz_pcap PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(fuzz_pcap ${fuzz_pcap_libs})

set(fuzz_print_src fuzz_print.c)
set(fuzz_print_libs netdissect ${TCPDUMP_LINK_LIBRARIES})

IF(DEFINED ENV{LIB_FUZZING_ENGINE})
	set(fuzz_print_libs ${fuzz_print_libs} $ENV{LIB_FUZZING_ENGINE})
else()
	set(fuzz_print_src ${fuzz_print_src} onefile.c)
endif()

add_executable(fuzz_print ${fuzz_print_src})
set_target_properties(fuzz_print PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(fuzz_print ${fuzz_print_libs})
