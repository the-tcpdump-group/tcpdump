#
# Try to find libpcap.
#

# Try to find the header
find_path(PCAP_INCLUDE_DIR pcap.h)

# Try to find the library
find_library(PCAP_LIBRARY pcap)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP
  DEFAULT_MSG
  PCAP_INCLUDE_DIR
  PCAP_LIBRARY
)

mark_as_advanced(
  PCAP_INCLUDE_DIR
  PCAP_LIBRARY
)
