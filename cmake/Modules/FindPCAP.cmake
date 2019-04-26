#
# Try to find libpcap.
#

#
# First, try pkg-config.
#
find_package(PkgConfig)
pkg_search_module(PCAP libpcap)

if(PCAP_FOUND)
  #
  # That worked.
  # Now, for each library, try to find it, so we get its full path.
  # CMake *really* doesn't like the notion of specifying "here are
  # the directories in which to look for libraries" except in
  # find_library() calls; it *really* prefers using full paths to
  # library files, rather than library names.
  #
  set(_pcap_libraries "${PCAP_LIBRARIES}")
  set(PCAP_LIBRARIES "")
  foreach(_lib IN LISTS _pcap_libraries)
    #
    # Try to find that library.
    #
    find_library(_libfullpath ${_lib} HINTS ${PCAP_LIBRARY_DIRS})
    list(APPEND PCAP_LIBRARIES ${_libfullpath})
    #
    # Remove that from the cache; we're using it as a local variable,
    # but find_library insists on making it a cache variable.
    #
    unset(_libfullpath CACHE)
  endforeach()

  #
  # Now find the static libraries.
  # (XXX - what about AIX?)
  #
  set(_pcap_static_libraries "${PCAP_STATIC_LIBRARIES}")
  set(PCAP_STATIC_LIBRARIES "")
  set(SAVED_CMAKE_FIND_LIBRARY_SUFFIXES "${CMAKE_FIND_LIBRARY_SUFFIXES}")
  set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
  foreach(_lib IN LISTS _pcap_static_libraries)
    #
    # Try to find that library, so we get its full path, as
    # we do with dynamic libraries.
    #
    find_library(_libfullpath ${_lib} HINTS ${PCAP_LIBRARY_DIRS})
    list(APPEND PCAP_STATIC_LIBRARIES ${_libfullpath})
    #
    # Remove that from the cache; we're using it as a local variable,
    # but find_library insists on making it a cache variable.
    #
    unset(_libfullpath CACHE)
  endforeach()
  set(CMAKE_FIND_LIBRARY_SUFFIXES "${SAVED_CMAKE_FIND_LIBRARY_SUFFIXES}")
else(PCAP_FOUND)
  #
  # That didn't work.  Try pcap-config.
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
    string(REGEX REPLACE "-I" "" _pcap_include_dir "${PCAP_CONFIG_OUTPUT}")

    # Try to find the header
    # We use what pcap-config provided as a hint, because the
    # pcap-config that ships with macOS bogusly supplies
    # -I/usr/local/include even though the header isn't
    # there (it may be under /usr/include or it may be
    # buried in the Xcode app bundle).
    find_path(PCAP_INCLUDE_DIRS pcap.h HINTS ${_pcap_include_dir})

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
    set(_pcap_library_dirs "")
    set(PCAP_LIBRARIES "")
    foreach(_arg IN LISTS LIBS_LIST)
      if(_arg MATCHES "^-L")
        # Add this directory to _pcap_library_dirs
        string(REGEX REPLACE "-L" "" _dir ${_arg})
        list(APPEND _pcap_library_dirs ${_dir})
      elseif(_arg MATCHES "^-l")
        string(REGEX REPLACE "-l" "" _lib ${_arg})
        #
        # Try to find that library, so we get its full path.  See the
        # comment above for why we do this.
        #
        # Furthermore, the pcap-config shipped with macOS reports
        # -I/usr/local/include for --cflags and -L/usr/local/lib for
        # --libs, rather than reporting the appropriate system (or
        # Xcode application) directory.
        #
        find_library(_libfullpath ${_lib} HINTS ${__pcap_library_dirs})
        list(APPEND PCAP_LIBRARIES ${_libfullpath})
        #
        # Remove that from the cache; we're using it as a local variable,
        # but find_library insists on making it a cache variable.
        #
        unset(_libfullpath CACHE)
      endif()
    endforeach()

    # Now, get the library directories and libraries for static linking.
    # (XXX - what about AIX?)
    execute_process(COMMAND "${PCAP_CONFIG}" "--libs" "--static"
      RESULT_VARIABLE PCAP_CONFIG_RESULT
      OUTPUT_VARIABLE PCAP_CONFIG_OUTPUT
    )
    if(NOT PCAP_CONFIG_RESULT EQUAL 0)
      message(FATAL_ERROR "pcap-config --libs --static failed")
    endif()
    separate_arguments(LIBS_LIST UNIX_COMMAND ${PCAP_CONFIG_OUTPUT})
    set(_pcap_static_library_dirs "")
    set(PCAP_STATIC_LIBRARIES "")
    set(SAVED_CMAKE_FIND_LIBRARY_SUFFIXES "${CMAKE_FIND_LIBRARY_SUFFIXES}")
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
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
        #
        # Remove that from the cache; we're using it as a local variable,
        # but find_library insists on making it a cache variable.
        #
        unset(_libfullpath CACHE)
      endif()
    endforeach()
    set(CMAKE_FIND_LIBRARY_SUFFIXES "${SAVED_CMAKE_FIND_LIBRARY_SUFFIXES}")
  else(PCAP_CONFIG)
    #
    # We don't have pcap-config.
    # Try to find the header by just looking for it in whatever
    # directories find_path() uses by default.
    #
    find_path(PCAP_INCLUDE_DIRS pcap.h)

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

    find_library(PCAP_LIBRARIES pcap)
    if(WIN32)
      if(NOT PCAP_LIBRARIES)
        #
        # OK, look for it under the name wpcap.
        #
        find_library(PCAP_LIBRARIES wpcap)
      endif(NOT PCAP_LIBRARIES)
    endif(WIN32)

    if(NOT WIN32)
      # Try to find the static library (XXX - what about AIX?)
      set(SAVED_CMAKE_FIND_LIBRARY_SUFFIXES "${CMAKE_FIND_LIBRARY_SUFFIXES}")
      set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
      find_library(PCAP_STATIC_LIBRARIES pcap)
      set(CMAKE_FIND_LIBRARY_SUFFIXES "${SAVED_CMAKE_FIND_LIBRARY_SUFFIXES}")
    endif(NOT WIN32)
  endif(PCAP_CONFIG)
endif(PCAP_FOUND)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCAP
  DEFAULT_MSG
  PCAP_INCLUDE_DIRS
  PCAP_LIBRARIES
)

mark_as_advanced(
  PCAP_INCLUDE_DIR
  PCAP_LIBRARY
  PCAP_STATIC_LIBRARY
)
