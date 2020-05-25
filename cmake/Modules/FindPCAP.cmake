#
# Try to find libpcap.
#
# To tell this module where to look, a user may set the environment variable
# PCAP_ROOT to point cmake to the *root* of a directory with include and
# lib subdirectories for pcap.dll (e.g WpdPack or npcap-sdk).
# Alternatively, PCAP_ROOT may also be set from cmake command line or GUI
# (e.g cmake -DPCAP_ROOT=C:\path\to\pcap [...])
#

if(WIN32)
  #
  # Building for Windows.
  #
  # libpcap isn't set up to install .pc files or pcap-config on Windows,
  # and it's not clear that either of them would work without a lot
  # of additional effort.  WinPcap doesn't supply them, and neither
  # does Npcap.
  #
  # So just search for them directly.  Look for both pcap and wpcap.
  # Don't bother looking for static libraries; unlike most UN*Xes
  # (with the exception of AIX), where different extensions are used
  # for shared and static, Windows uses .lib both for import libraries
  # for DLLs and for static libraries.
  #
  # We don't directly set PCAP_INCLUDE_DIRS or PCAP_LIBRARIES, as
  # they're not supposed to be cache entries, and find_path() and
  # find_library() set cache entries.
  #
  find_path(PCAP_INCLUDE_DIR pcap.h)

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
  find_library(PCAP_LIBRARY NAMES pcap wpcap)

  #
  # Do the standard arg processing, including failing if it's a
  # required package.
  #
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
  if(PCAP_FOUND)
    set(PCAP_LIBRARIES ${PCAP_LIBRARY})
    set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
  endif()
else(WIN32)
  #
  # Building for UN*X.
  #
  # See whether we were handed a QUIET argument, so we can pass it on
  # to pkg_search_module.  Do *NOT* pass on the REQUIRED argument,
  # because, if pkg-config isn't found, or it is but it has no .pc
  # files for libpcap, that is *not* necessarily an indication that
  # libpcap isn't available - not all systems ship pkg-config, and
  # libpcap didn't have .pc files until libpcap 1.9.0.
  #
  if(PCAP_FIND_QUIETLY)
    set(_quiet "QUIET")
  endif()

  #
  # First, try pkg-config.
  #
  find_package(PkgConfig)
  pkg_search_module(CONFIG_PCAP ${_quiet} libpcap)

  if(NOT CONFIG_PCAP_FOUND)
    #
    # That didn't work.  Try pcap-config.
    #
    find_program(PCAP_CONFIG pcap-config)
    if(PCAP_CONFIG)
      #
      # We have pcap-config; use it.
      #
      if(NOT "${_quiet}" STREQUAL "QUIET")
        message(STATUS "Found pcap-config")
      endif()

      #
      # if this is macOS or some other Darwin-based OS, check whether
      # it's the system-supplied one.
      #
      if(APPLE AND "${PCAP_CONFIG}" STREQUAL /usr/bin/pcap-config)
        #
        # It is - remember that, so that if it provides -I/usr/local/include
        # with --cflags, or -L/usr/local/lib with --libs, we ignore it;
        # the macOS pcap-config does that even though the headers aren't
        # under /usr/local/include and the library isn't in /usr/local/lib.
        #
        set(_broken_apple_pcap_config TRUE)
      endif()

      #
      # Now get the include directories.
      #
      execute_process(COMMAND "${PCAP_CONFIG}" "--cflags"
        RESULT_VARIABLE PCAP_CONFIG_RESULT
        OUTPUT_VARIABLE PCAP_CONFIG_OUTPUT
        OUTPUT_STRIP_TRAILING_WHITESPACE
      )
      if(NOT PCAP_CONFIG_RESULT EQUAL 0)
        message(FATAL_ERROR "pcap-config --cflags failed")
      endif()
      separate_arguments(CFLAGS_LIST UNIX_COMMAND ${PCAP_CONFIG_OUTPUT})
      set(CONFIG_PCAP_INCLUDE_DIRS "")
      foreach(_arg IN LISTS CFLAGS_LIST)
        if(_arg MATCHES "^-I")
          #
          # Extract the directory by removing the -I.
          #
          string(REGEX REPLACE "-I" "" _dir ${_arg})
          #
          # Work around macOS (and probably other Darwin) brokenness,
          # by not adding /usr/local/include if it's from the broken
          # Apple pcap-config.
          #
          if(NOT _broken_apple_pcap_config OR
             NOT "${_dir}" STREQUAL /usr/local/include)
            # Add it to CONFIG_PCAP_INCLUDE_DIRS
            list(APPEND CONFIG_PCAP_INCLUDE_DIRS ${_dir})
          endif()
        endif()
      endforeach()

      #
      # Now, get the library directories and libraries for dynamic linking.
      #
      execute_process(COMMAND "${PCAP_CONFIG}" "--libs"
        RESULT_VARIABLE PCAP_CONFIG_RESULT
        OUTPUT_VARIABLE PCAP_CONFIG_OUTPUT
        OUTPUT_STRIP_TRAILING_WHITESPACE
      )
      if(NOT PCAP_CONFIG_RESULT EQUAL 0)
        message(FATAL_ERROR "pcap-config --libs failed")
      endif()
      separate_arguments(LIBS_LIST UNIX_COMMAND ${PCAP_CONFIG_OUTPUT})
      set(CONFIG_PCAP_LIBRARY_DIRS "")
      set(CONFIG_PCAP_LIBRARIES "")
      foreach(_arg IN LISTS LIBS_LIST)
        if(_arg MATCHES "^-L")
          #
          # Extract the directory by removing the -L.
          #
          string(REGEX REPLACE "-L" "" _dir ${_arg})
          #
          # Work around macOS (and probably other Darwin) brokenness,
          # by not adding /usr/local/lib if it's from the broken
          # Apple pcap-config.
          #
          if(NOT _broken_apple_pcap_config OR
             NOT "${_dir}" STREQUAL /usr/local/lib)
            # Add this directory to CONFIG_PCAP_LIBRARY_DIRS
            list(APPEND CONFIG_PCAP_LIBRARY_DIRS ${_dir})
          endif()
        elseif(_arg MATCHES "^-l")
          string(REGEX REPLACE "-l" "" _lib ${_arg})
          list(APPEND CONFIG_PCAP_LIBRARIES ${_lib})
        endif()
      endforeach()

      #
      # Now, get the library directories and libraries for static linking.
      #
      execute_process(COMMAND "${PCAP_CONFIG}" "--libs" "--static"
        RESULT_VARIABLE PCAP_CONFIG_RESULT
        OUTPUT_VARIABLE PCAP_CONFIG_OUTPUT
      )
      if(NOT PCAP_CONFIG_RESULT EQUAL 0)
        message(FATAL_ERROR "pcap-config --libs --static failed")
      endif()
      separate_arguments(LIBS_LIST UNIX_COMMAND ${PCAP_CONFIG_OUTPUT})
      set(CONFIG_PCAP_STATIC_LIBRARY_DIRS "")
      set(CONFIG_PCAP_STATIC_LIBRARIES "")
      foreach(_arg IN LISTS LIBS_LIST)
        if(_arg MATCHES "^-L")
          #
          # Extract the directory by removing the -L.
          #
          string(REGEX REPLACE "-L" "" _dir ${_arg})
          #
          # Work around macOS (and probably other Darwin) brokenness,
          # by not adding /usr/local/lib if it's from the broken
          # Apple pcap-config.
          #
          if(NOT _broken_apple_pcap_config OR
             NOT "${_dir}" STREQUAL /usr/local/lib)
            # Add this directory to CONFIG_PCAP_STATIC_LIBRARY_DIRS
            list(APPEND CONFIG_PCAP_STATIC_LIBRARY_DIRS ${_dir})
          endif()
        elseif(_arg MATCHES "^-l")
          string(REGEX REPLACE "-l" "" _lib ${_arg})
          #
          # Try to find that library, so we get its full path, as
          # we do with dynamic libraries.
          #
          list(APPEND CONFIG_PCAP_STATIC_LIBRARIES ${_lib})
        endif()
      endforeach()

      #
      # We've set CONFIG_PCAP_INCLUDE_DIRS, CONFIG_PCAP_LIBRARIES, and
      # CONFIG_PCAP_STATIC_LIBRARIES above; set CONFIG_PCAP_FOUND.
      #
      set(CONFIG_PCAP_FOUND YES)
    endif()
  endif()

  #
  # If CONFIG_PCAP_FOUND is set, we have information from pkg-config and
  # pcap-config; we need to convert library names to library full paths.
  #
  # If it's not set, we have to look for the libpcap headers and library
  # ourselves.
  #
  if(CONFIG_PCAP_FOUND)
    #
    # Use CONFIG_PCAP_INCLUDE_DIRS as the value for PCAP_INCLUDE_DIRS.
    #
    set(PCAP_INCLUDE_DIRS "${CONFIG_PCAP_INCLUDE_DIRS}")

    #
    # CMake *really* doesn't like the notion of specifying
    # "here are the directories in which to look for libraries"
    # except in find_library() calls; it *really* prefers using
    # full paths to library files, rather than library names.
    #
    foreach(_lib IN LISTS CONFIG_PCAP_LIBRARIES)
      find_library(_libfullpath ${_lib} HINTS ${CONFIG_PCAP_LIBRARY_DIRS})
      list(APPEND PCAP_LIBRARIES ${_libfullpath})
      #
      # Remove that from the cache; we're using it as a local variable,
      # but find_library insists on making it a cache variable.
      #
      unset(_libfullpath CACHE)
   endforeach()

    #
    # Now do the same for the static libraries.
    #
    set(SAVED_CMAKE_FIND_LIBRARY_SUFFIXES "${CMAKE_FIND_LIBRARY_SUFFIXES}")
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    foreach(_lib IN LISTS CONFIG_PCAP_STATIC_LIBRARIES)
      find_library(_libfullpath ${_lib} HINTS ${CONFIG_PCAP_LIBRARY_DIRS})
      list(APPEND PCAP_STATIC_LIBRARIES ${_libfullpath})
      #
      # Remove that from the cache; we're using it as a local variable,
      # but find_library insists on making it a cache variable.
      #
      unset(_libfullpath CACHE)
    endforeach()
    set(CMAKE_FIND_LIBRARY_SUFFIXES "${SAVED_CMAKE_FIND_LIBRARY_SUFFIXES}")

    #
    # We found libpcap using pkg-config or pcap-config.
    #
    set(PCAP_FOUND YES)
  else(CONFIG_PCAP_FOUND)
    #
    # We didn't have pkg-config, or we did but it didn't have .pc files
    # for libpcap, and we don't have pkg-config, so we have to look for
    # the headers and libraries ourself.
    #
    # We don't directly set PCAP_INCLUDE_DIRS or PCAP_LIBRARIES, as
    # they're not supposed to be cache entries, and find_path() and
    # find_library() set cache entries.
    #
    # Try to find the header file.
    #
    find_path(PCAP_INCLUDE_DIR pcap.h)

    #
    # Try to find the library
    #
    find_library(PCAP_LIBRARY pcap)

    # Try to find the static library (XXX - what about AIX?)
    set(SAVED_CMAKE_FIND_LIBRARY_SUFFIXES "${CMAKE_FIND_LIBRARY_SUFFIXES}")
    set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
    find_library(PCAP_STATIC_LIBRARY pcap)
    set(CMAKE_FIND_LIBRARY_SUFFIXES "${SAVED_CMAKE_FIND_LIBRARY_SUFFIXES}")

    #
    # This will fail if REQUIRED is set and PCAP_INCLUDE_DIR or
    # PCAP_LIBRARY aren't set.
    #
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

    if(PCAP_FOUND)
      set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
      set(PCAP_LIBRARIES ${PCAP_LIBRARY})
      set(PCAP_STATIC_LIBRARIES ${PCAP_STATIC_LIBRARY})
    endif(PCAP_FOUND)
  endif(CONFIG_PCAP_FOUND)
endif(WIN32)
