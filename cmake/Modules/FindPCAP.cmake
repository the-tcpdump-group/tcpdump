#
# Try to find libpcap.
#

find_program(PCAP_CONFIG pcap-config)
if(PCAP_CONFIG)
  # We have pcap-config; use it.
  # First, get the include directory.
  execute_process(COMMAND "${PCAP_CONFIG}" "--cflags"
    RESULT_VARIABLE PCAP_CONFIG_RESULT
    OUTPUT_VARIABLE PCAP_CONFIG_OUTPUT
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if(NOT PCAP_CONFIG_RESULT EQUAL 0)
    message(FATAL_ERROR "pcap-config --cflags failed")
  endif()
  string(REGEX REPLACE "-I" "" PCAP_INCLUDE_DIR ${PCAP_CONFIG_OUTPUT})

  # Now, get the library directories and libraries.
  execute_process(COMMAND "${PCAP_CONFIG}" "--libs"
    RESULT_VARIABLE PCAP_CONFIG_RESULT
    OUTPUT_VARIABLE PCAP_CONFIG_OUTPUT
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if(NOT PCAP_CONFIG_RESULT EQUAL 0)
    message(FATAL_ERROR "pcap-config --libs failed")
  endif()
  separate_arguments(LIBS_LIST UNIX_COMMAND ${PCAP_CONFIG_OUTPUT})
  set(PCAP_LIBRARY_DIRS)
  set(PCAP_LIBRARIES)
  foreach(arg IN LISTS LIBS_LIST)
    if(arg MATCHES "^-L")
      # Add this directory to PCAP_LIBRARY_DIRS
      string(REGEX REPLACE "-L" "" dir ${arg})
      list(APPEND PCAP_LIBRARY_DIRS ${dir})
    elseif(arg MATCHES "^-l")
      string(REGEX REPLACE "-l" "" lib ${arg})
      list(APPEND PCAP_LIBRARIES ${lib})
    endif()
  endforeach()

  # Now, get the library directories and libraries for static linking.
  execute_process(COMMAND "${PCAP_CONFIG}" "--libs" "--static"
    RESULT_VARIABLE PCAP_CONFIG_RESULT
    OUTPUT_VARIABLE PCAP_CONFIG_OUTPUT
  )
  if(NOT PCAP_CONFIG_RESULT EQUAL 0)
    message(FATAL_ERROR "pcap-config --libs --static failed")
  endif()
  separate_arguments(LIBS_LIST UNIX_COMMAND ${PCAP_CONFIG_OUTPUT})
  set(PCAP_STATIC_LIBRARY_DIRS)
  set(PCAP_STATIC_LIBRARIES)
  foreach(arg IN LISTS LIBS_LIST)
    if(arg MATCHES "^-L")
      # Add this directory to PCAP_STATIC_LIBRARY_DIRS
      string(REGEX REPLACE "-L" "" dir ${arg})
      list(APPEND PCAP_STATIC_LIBRARY_DIRS ${dir})
    elseif(flag MATCHES "^-l")
      string(REGEX REPLACE "-l" "" lib ${arg})
      list(APPEND PCAP_STATIC_LIBRARIES ${lib})
    endif()
  endforeach()

  # Try to find the header
  find_path(PCAP_INCLUDE_DIR pcap.h HINTS ${PCAP_INCLUDE_DIRS})

  # Try to find the library
  find_library(PCAP_LIBRARY pcap HINTS ${PCAP_LIBRARY_DIRS})

  # Try to find the static library (XXX - what about AIX?)
  include(CMakePushCheckState)
  cmake_push_check_state()
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  find_library(PCAP_STATIC_LIBRARY pcap HINTS ${PCAP_STATIC_LIBRARY_DIRS})
  cmake_pop_check_state()
else(PCAP_CONFIG)
  # Try to find the header
  find_path(PCAP_INCLUDE_DIR pcap.h)

  # Try to find the library
  find_library(PCAP_LIBRARY pcap)

  # Try to find the static library (XXX - what about AIX?)
  include(CMakePushCheckState)
  cmake_push_check_state()
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  find_library(PCAP_STATIC_LIBRARY pcap)
  cmake_pop_check_state()

  set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
  set(PCAP_LIBRARIES ${PCAP_LIBRARY})
endif(PCAP_CONFIG)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP
  DEFAULT_MSG
  PCAP_INCLUDE_DIR
  PCAP_LIBRARY
)

mark_as_advanced(
  PCAP_INCLUDE_DIR
  PCAP_LIBRARY
  PCAP_STATIC_LIBRARY
)
