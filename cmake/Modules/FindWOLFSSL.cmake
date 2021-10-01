#
# Try to find libwolfssl.
#

# Try to find options.h
find_path(WOLFSSL_INCLUDE_DIR wolfssl/options.h)

# Try to find the library
find_library(WOLFSSL_LIBRARY wolfssl)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(WOLFSSL
  DEFAULT_MSG
  WOLFSSL_INCLUDE_DIR
  WOLFSSL_LIBRARY
)

mark_as_advanced(
  WOLFSSL_INCLUDE_DIR
  WOLFSSL_LIBRARY
)

set(WOLFSSL_INCLUDE_DIRS ${WOLFSSL_INCLUDE_DIR})
set(WOLFSSL_LIBRARIES ${WOLFSSL_LIBRARY})
