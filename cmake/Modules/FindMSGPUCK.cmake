#
# try to find msgpuck.
#

# Try to find the header
find_path(MSGPUCK_INCLUDE_DIR msgpuck.h)

# Try to find the library
find_library(MSGPUCK_LIBRARY msgpuck)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MSGPUCK
  DEFAULT_MSG
  MSGPUCK_INCLUDE_DIR
  MSGPUCK_LIBRARY
)

mark_as_advanced(
  MSGPUCK_INCLUDE_DIR
  MSGPUCK_LIBRARY
)

set(MSGPUCK_INCLUDE_DIRS ${MSGPUCK_INCLUDE_DIR})
set(MSGPUCK_LIBRARIES ${MSGPUCK_LIBRARY})
