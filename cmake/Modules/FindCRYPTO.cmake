#
# Try to find libcrypto.
#

if(MSVC)
  find_package(OpenSSL QUIET)
endif()

# Try to find the header
find_path(CRYPTO_INCLUDE_DIR openssl/crypto.h
  HINTS
    ${OPENSSL_INCLUDE_DIR}
)

# Try to find the library
if(NOT MSVC)
  find_library(CRYPTO_LIBRARY crypto)
else()
  if(USE_STATIC_RT)
    set(OPENSSL_MSVC_STATIC_RT 1)
  endif()
  # going the extra mile...
  set(CRYPTO_LIBRARY_RELEASE ${LIB_EAY_RELEASE})
  set(CRYPTO_LIBRARY_DEBUG ${LIB_EAY_DEBUG})
  include(SelectLibraryConfigurations)
  select_library_configurations(CRYPTO)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(CRYPTO
  DEFAULT_MSG
  CRYPTO_INCLUDE_DIR
  CRYPTO_LIBRARY
)

mark_as_advanced(
  CRYPTO_INCLUDE_DIR
  CRYPTO_LIBRARY
)

set(CRYPTO_INCLUDE_DIRS ${CRYPTO_INCLUDE_DIR})
set(CRYPTO_LIBRARIES ${CRYPTO_LIBRARY})
