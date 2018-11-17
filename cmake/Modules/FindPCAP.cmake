#
# Try to find libpcap.
#

find_program(PCAP_CONFIG pcap-config)
if(PCAP_CONFIG)
  #
  # We have pcap-config; use it.
  # XXX - what if this is on Windows?  If you're using, for example,
  # MinGW, that might be the right thing to do, *if* pcap-config
  # were made to work properly on Windows, but what about MSVC?
  #
  # First, get the include directory.
  #
  execute_process(COMMAND "${PCAP_CONFIG}" "--cflags"
    RESULT_VARIABLE PCAP_CONFIG_RESULT
    OUTPUT_VARIABLE PCAP_CONFIG_OUTPUT
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if(NOT PCAP_CONFIG_RESULT EQUAL 0)
    message(FATAL_ERROR "pcap-config --cflags failed")
  endif()
  #
  # XXX - this assumes that there's only one -I flag in the output
  # of pcap-config --cflags.  That *should* be the case.
  #
  string(REGEX REPLACE "-I" "" PCAP_INCLUDE_DIRS "${PCAP_CONFIG_OUTPUT}")
  set(PCAP_INCLUDE_DIR ${PCAP_INCLUDE_DIRS})

  # Now, get the libraries.
  execute_process(COMMAND "${PCAP_CONFIG}" "--libs"
    RESULT_VARIABLE PCAP_CONFIG_RESULT
    OUTPUT_VARIABLE PCAP_CONFIG_OUTPUT
    OUTPUT_STRIP_TRAILING_WHITESPACE
  )
  if(NOT PCAP_CONFIG_RESULT EQUAL 0)
    message(FATAL_ERROR "pcap-config --libs failed")
  endif()
  separate_arguments(LIBS_LIST UNIX_COMMAND ${PCAP_CONFIG_OUTPUT})
  set(_pcap_library_dirs)
  set(PCAP_LIBRARIES)
  foreach(_arg IN LISTS LIBS_LIST)
    if(_arg MATCHES "^-L")
      # Add this directory to _pcap_library_dirs
      string(REGEX REPLACE "-L" "" _dir ${_arg})
      list(APPEND _pcap_library_dirs ${_dir})
    elseif(_arg MATCHES "^-l")
      string(REGEX REPLACE "-l" "" _lib ${_arg})
      #
      # Try to find that library, so we get its full path.
      # CMake *really* doesn't like the notion of specifying "here are
      # the directories in which to look for libraries" except in
      # find_library() calls; it *really* prefers using full paths to
      # library files, rather than library names.
      #
      find_library(_libfullpath ${_lib} HINTS ${__pcap_library_dirs})
      list(APPEND PCAP_LIBRARIES ${_libfullpath})
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
  set(_pcap_static_library_dirs)
  set(PCAP_STATIC_LIBRARIES)
  foreach(_arg IN LISTS LIBS_LIST)
    if(_arg MATCHES "^-L")
      # Add this directory to _pcap_static_library_dirs
      string(REGEX REPLACE "-L" "" _dir ${_arg})
      list(APPEND _pcap_static_library_dirs ${_dir})
    elseif(_arg MATCHES "^-l")
      string(REGEX REPLACE "-l" "" _lib ${_arg})
      #
      # Try to find that library, so we get its full path, as
      # we do with dynamic libraries.
      #
      find_library(_libfullpath ${_lib} HINTS ${__pcap_static_library_dirs})
      list(APPEND PCAP_STATIC_LIBRARIES ${_libfullpath})
    endif()
  endforeach()

  # Try to find the header
  find_path(PCAP_INCLUDE_DIR pcap.h HINTS ${PCAP_INCLUDE_DIRS})

  # Try to find the library
  find_library(PCAP_LIBRARY pcap HINTS ${_pcap_library_dirs})

  # Try to find the static library (XXX - what about AIX?)
  include(CMakePushCheckState)
  cmake_push_check_state()
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  find_library(PCAP_STATIC_LIBRARY pcap HINTS ${_pcap_static_library_dirs})
  cmake_pop_check_state()
else(PCAP_CONFIG)
  # Try to find the header
  find_path(PCAP_INCLUDE_DIR pcap.h)

  # Try to find the library
  if(WIN32)
    # The 64-bit Packet.lib is located under /x64
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
      #
      # For the WinPcap and Npcap SDKs, the Lib subdirectory of the top-level
      # directory contains 32-bit libraries; the 64-bit libraries are in the
      # Lib/x64 directory.
      #
      # The only way to *FORCE* CMake to look in the Lib/x64 directory
      # without searching in the Lib directory first appears to be to set
      # CMAKE_LIBRARY_ARCHITECTURE to "x64".
      #
      set(CMAKE_LIBRARY_ARCHITECTURE "x64")
    endif()
  endif()

  find_library(PCAP_LIBRARY pcap)
  if(WIN32)
    if(NOT PCAP_LIBRARY)
      #
      # OK, look for it under the name wpcap.
      #
      find_library(PCAP_LIBRARY wpcap)
    endif(NOT PCAP_LIBRARY)
  endif(WIN32)
  if(NOT WIN32)
    # Try to find the static library (XXX - what about AIX?)
    include(CMakePushCheckState)
    cmake_push_check_state()
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    find_library(PCAP_STATIC_LIBRARY pcap)
    cmake_pop_check_state()
  endif(NOT WIN32)

  set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
  set(PCAP_LIBRARIES ${PCAP_LIBRARY})
  set(PCAP_STATIC_LIBRARIES ${PCAP_STATIC_LIBRARY})
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
