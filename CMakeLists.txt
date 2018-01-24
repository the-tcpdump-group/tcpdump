cmake_minimum_required(VERSION 2.8.6)

set(CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/Modules)

project(tcpdump)

#
# Try to enable as many C99 features as we can.
# At minimum, we want C++/C99-style // comments.
# (Sadly, this won't work with CMake prior to 3.1.)
#
set(CMAKE_C_STANDARD 99)

set(LIBRARY_NAME netdissect)

###################################################################
#   Parameters
###################################################################

option(WITH_SMI "Build with libsmi, if available" ON)
option(WITH_CRYPTO "Build with OpenSSL/libressl libcrypto, if available" ON)
option(WITH_CAPSICUM "Build with Capsicum security functions, if available" ON)
option(WITH_CAP_NG "Use libcap-ng, if available" ON)
option(ENABLE_SMB "Build with the SMB dissector" ON)

#
# String parameters.  Neither of them are set, initially; only if the
# user explicitly configures them are they set.
#
# WITH_CHROOT is STRING, not PATH, as the directory need not exist
# when CMake is run.
#
set(WITH_CHROOT CACHE STRING
    "Directory to which to chroot when dropping privileges")
set(WITH_USER CACHE STRING
    "User to whom to set the UID when dropping privileges")

#
# By default, build universal with the appropriate set of architectures
# for the OS on which we're doing the build.
#
if(APPLE AND "${CMAKE_OSX_ARCHITECTURES}" STREQUAL "")
    #
    # Get the major version of Darwin.
    #
    string(REGEX MATCH "^([0-9]+)" SYSTEM_VERSION_MAJOR "${CMAKE_SYSTEM_VERSION}")

    if(SYSTEM_VERSION_MAJOR EQUAL 9)
        #
        # Leopard.  Build for x86 and 32-bit PowerPC, with
        # x86 first.  (That's what Apple does.)
        #
        set(CMAKE_OSX_ARCHITECTURES "i386;ppc")
    elseif(SYSTEM_VERSION_MAJOR EQUAL 10)
        #
        # Snow Leopard.  Build for x86-64 and x86, with
        # x86-64 first.  (That's what Apple does.)
        #
        set(CMAKE_OSX_ARCHITECTURES "x86_64;i386")
    endif()
endif()

###################################################################
#   Versioning
###################################################################

# Get, parse, format and set tcpdump's version string from
# [tcpdump_root]/VERSION for later use.
 
# Get MAJOR, MINOR, PATCH & SUFFIX
file(STRINGS ${tcpdump_SOURCE_DIR}/VERSION
    PACKAGE_VERSION
    LIMIT_COUNT 1 # Read only the first line
)

######################################
# Project settings
######################################

add_definitions(-DHAVE_CONFIG_H)

include_directories(
    ${CMAKE_CURRENT_BINARY_DIR}
    ${tcpdump_SOURCE_DIR}
)

if(MSVC)
    add_definitions(-D__STDC__)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
endif(MSVC)

if(MSVC)
    if (USE_STATIC_RT)
        MESSAGE(STATUS "Use STATIC runtime")
        set(NAME_RT MT)
        set (CMAKE_CXX_FLAGS_MINSIZEREL     "${CMAKE_CXX_FLAGS_MINSIZEREL} /MT")
        set (CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /MT")
        set (CMAKE_CXX_FLAGS_RELEASE        "${CMAKE_CXX_FLAGS_RELEASE} /MT")
        set (CMAKE_CXX_FLAGS_DEBUG          "${CMAKE_CXX_FLAGS_DEBUG} /MTd")

        set (CMAKE_C_FLAGS_MINSIZEREL       "${CMAKE_C_FLAGS_MINSIZEREL} /MT")
        set (CMAKE_C_FLAGS_RELWITHDEBINFO   "${CMAKE_C_FLAGS_RELWITHDEBINFO} /MT")
        set (CMAKE_C_FLAGS_RELEASE          "${CMAKE_C_FLAGS_RELEASE} /MT")
        set (CMAKE_C_FLAGS_DEBUG            "${CMAKE_C_FLAGS_DEBUG} /MTd")
    else (USE_STATIC_RT)
        MESSAGE(STATUS "Use DYNAMIC runtime")
        set(NAME_RT MD)
        set (CMAKE_CXX_FLAGS_MINSIZEREL     "${CMAKE_CXX_FLAGS_MINSIZEREL} /MD")
        set (CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /MD")
        set (CMAKE_CXX_FLAGS_RELEASE        "${CMAKE_CXX_FLAGS_RELEASE} /MD")
        set (CMAKE_CXX_FLAGS_DEBUG          "${CMAKE_CXX_FLAGS_DEBUG} /MDd")

        set (CMAKE_C_FLAGS_MINSIZEREL       "${CMAKE_C_FLAGS_MINSIZEREL} /MD")
        set (CMAKE_C_FLAGS_RELWITHDEBINFO   "${CMAKE_C_FLAGS_RELWITHDEBINFO} /MD")
        set (CMAKE_C_FLAGS_RELEASE          "${CMAKE_C_FLAGS_RELEASE} /MD")
        set (CMAKE_C_FLAGS_DEBUG            "${CMAKE_C_FLAGS_DEBUG} /MDd")
   endif (USE_STATIC_RT)
endif(MSVC)

###################################################################
#   Detect available platform features
###################################################################

include(CMakePushCheckState)
include(CheckIncludeFile)
include(CheckIncludeFiles)
include(CheckFunctionExists)
include(CheckSymbolExists)
include(CheckStructHasMember)
include(CheckTypeSize)

#
# Header files.
#
check_include_file(fcntl.h HAVE_FCNTL_H)
check_include_file(rpc/rpc.h HAVE_RPC_RPC_H)
if(HAVE_RPC_RPC_H)
    check_include_files("rpc/rpc.h;rpc/rpcent.h" HAVE_RPC_RPCENT_H)
endif(HAVE_RPC_RPC_H)
check_include_file(netdnet/dnetdb.h HAVE_NETDNET_DNETDB_H)
check_include_files("sys/types.h;sys/socket.h;net/if.h;net/pfvar.h" HAVE_NET_PFVAR_H)
if(HAVE_NET_PFVAR_H)
    check_include_files("sys/types.h;sys/socket.h;net/if.h;net/pfvar.h;net/if_pflog.h" HAVE_NET_IF_PFLOG_H)
    if(HAVE_NET_IF_PFLOG_H)
        set(LOCALSRC print-pflog.c ${LOCALSRC})
    endif(HAVE_NET_IF_PFLOG_H)
endif(HAVE_NET_PFVAR_H)

#
# You are in a twisty little maze of UN*Xes, all different.
# Some might not have ether_ntohost().
# Some might have it and declare it in <net/ethernet.h>.
# Some might have it and declare it in <netinet/ether.h>
# Some might have it and declare it in <sys/ethernet.h>.
# Some might have it and declare it in <arpa/inet.h>.
# Some might have it and declare it in <netinet/if_ether.h>.
# Some might have it and not declare it in any header file.
#
# Before you is a C compiler.
#
check_function_exists(ether_ntohost HAVE_ETHER_NTOHOST)
if(HAVE_ETHER_NTOHOST)
    #
    # OK, we have ether_ntohost().  We don't check whether it's buggy,
    # as we assume any system that has CMake is likely to be new enough
    # that, if it has ether_ntohost(), whatever bug is checked for in
    # autotools is fixed; we just decide to use it.
    #
    set(USE_ETHER_NTOHOST TRUE)

    #
    # Is it declared in <net/ethernet.h>?
    #
    # This test fails if we don't have <net/ethernet.h> or if we do
    # but it doesn't declare ether_ntohost().
    #
    check_symbol_exists(ether_ntohost net/ethernet.h NET_ETHERNET_H_DECLARES_ETHER_NTOHOST)
    if(NET_ETHERNET_H_DECLARES_ETHER_NTOHOST)
        #
        # Yes - we have it declared.
        #
        set(HAVE_DECL_ETHER_NTOHOST TRUE)
    endif()
    #
    # Did that succeed?
    #
    if(NOT HAVE_DECL_ETHER_NTOHOST)
        #
        # No - how about <netinet/ether.h>, as on Linux?
        #
        # This test fails if we don't have <netinet/ether.h>
        # or if we do but it doesn't declare ether_ntohost().
        #
        check_symbol_exists(ether_ntohost netinet/ether.h NETINET_ETHER_H_DECLARES_ETHER_NTOHOST)
        if(NETINET_ETHER_H_DECLARES_ETHER_NTOHOST)
            #
            # Yes - we have it declared.
            #
            set(HAVE_DECL_ETHER_NTOHOST TRUE)
        endif()
    endif()
    #
    # Did that succeed?
    #
    if(NOT HAVE_DECL_ETHER_NTOHOST)
        #
        # No - how about <sys/ethernet.h>, as on Solaris 10 and later?
        #
        # This test fails if we don't have <sys/ethernet.h>
        # or if we do but it doesn't declare ether_ntohost().
        #
        check_symbol_exists(ether_ntohost sys/ethernet.h SYS_ETHERNET_H_DECLARES_ETHER_NTOHOST)
        if(SYS_ETHERNET_H_DECLARES_ETHER_NTOHOST)
            #
            # Yes - we have it declared.
            #
            set(HAVE_DECL_ETHER_NTOHOST TRUE)
        endif()
    endif()
    #
    # Did that succeed?
    #
    if(NOT HAVE_DECL_ETHER_NTOHOST)
        #
        # No, how about <arpa/inet.h>, as on AIX?
        #
        # This test fails if we don't have <arpa/inet.h>
        # or if we do but it doesn't declare ether_ntohost().
        #
        check_symbol_exists(ether_ntohost arpa/inet.h ARPA_INET_H_DECLARES_ETHER_NTOHOST)
        if(ARPA_INET_H_DECLARES_ETHER_NTOHOST)
            #
            # Yes - we have it declared.
            #
            set(HAVE_DECL_ETHER_NTOHOST TRUE)
        endif()
    endif()
    #
    # Did that succeed?
    #
    if(NOT HAVE_DECL_ETHER_NTOHOST)
        #
        # No, how about <netinet/if_ether.h>?
        # On some platforms, it requires <net/if.h> and
        # <netinet/in.h>, and we always include it with
        # both of them, so test it with both of them.
        #
        # This test fails if we don't have <netinet/if_ether.h>
        # and the headers we include before it, or if we do but
        # <netinet/if_ether.h> doesn't declare ether_ntohost().
        #
        check_symbol_exists(ether_ntohost "sys/types.h;sys/socket.h;net/if.h;netinet/in.h;netinet/if_ether.h" NETINET_IF_ETHER_H_DECLARES_ETHER_NTOHOST)
        if(NETINET_IF_ETHER_H_DECLARES_ETHER_NTOHOST)
            #
            # Yes - we have it declared.
            #
            set(HAVE_DECL_ETHER_NTOHOST TRUE)
        endif()
    endif()
    #
    # After all that, is ether_ntohost() declared?
    #
    if(NOT HAVE_DECL_ETHER_NTOHOST)
        #
        # No, we'll have to declare it ourselves.
        # Do we have "struct ether_addr" if we include<netinet/if_ether.h>?
        #
        check_struct_has_member("struct ether_addr" octet "sys/types.h;sys/socket.h;net/if.h;netinet/in.h;netinet/if_ether.h" HAVE_STRUCT_ETHER_ADDR)
    endif()
endif()

#
# As the autoconf manual says, AC_HEADER_TIME is obsolete, as all UN*Xes
# let you include both time.h and sys/time.h, so just say we can.
#
check_include_file(bitypes.h HAVE_SYS_BITYPES_H)
check_include_file(limits.h HAVE_LIMITS_H)

#
# Check whether we have pcap/pcap-inttypes.h.
# If we do, we use that to get the C99 types defined.
#
check_include_file(pcap/pcap-inttypes.h HAVE_PCAP_PCAP_INTTYPES_H)

#
# Check for some headers introduced in later versions of libpcap
# and used by some printers.
#
# Those headers might use the {u_}intN_t types, so we must include
# netdissect-stdinc.h first.
#
cmake_push_check_state()
set(CMAKE_EXTRA_INCLUDE_FILES netdissect-stdinc.h)
check_include_file(pcap/bluetooth.h HAVE_PCAP_BLUETOOTH_H)
check_include_file(pcap/nflog.h HAVE_PCAP_NFLOG_H)
cmake_pop_check_state()

#
# Functions.
#
check_function_exists(strlcat HAVE_STRLCAT)
check_function_exists(strlcpy HAVE_STRLCPY)
check_function_exists(strdup HAVE_STRDUP)
check_function_exists(strsep HAVE_STRSEP)
check_function_exists(getservent HAVE_GETSERVENT)
check_function_exists(getopt_long HAVE_GETOPT_LONG)
check_function_exists(vsnprintf HAVE_VSNPRINTF)
check_function_exists(snprintf HAVE_SNPRINTF)
check_function_exists(fork HAVE_FORK)
check_function_exists(vfork HAVE_VFORK)
check_function_exists(strftime HAVE_STRFTIME)
check_function_exists(setlinebuf HAVE_SETLINEBUF)

check_function_exists(getrpcbynumber HAVE_GETRPCBYNUMBER_STDLIBS)
if(HAVE_GETRPCBYNUMBER_STDLIBS)
    set(HAVE_GETRPCBYNUMBER TRUE)
else(HAVE_GETRPCBYNUMBER_STDLIBS)
    #
    # Some platforms may need -lnsl for getrpcbynumber.
    #
    cmake_push_check_state()
    set(CMAKE_REQUIRED_LIBRARIES nsl)
    check_function_exists(getrpcbynumber HAVE_GETRPCBYNUMBER)
    cmake_pop_check_state()
endif(HAVE_GETRPCBYNUMBER_STDLIBS)

#
# Data types.
#
# XXX - there's no check_struct() macro that's like check_struct_has_member()
# except that it only checks for the existence of the structure type,
# so we use check_struct_has_member() and look for ss_family.
#
check_struct_has_member("struct sockaddr_storage" ss_family sys/socket.h  HAVE_SOCKADDR_STORAGE)
set(CMAKE_EXTRA_INCLUDE_FILES unistd.h sys/socket.h)
check_type_size("socklen_t" SOCKLEN_T)
set(CMAKE_EXTRA_INCLUDE_FILES unistd.h)

#
# Check for IPv6 support.
# We just check for AF_INET6 and struct in6_addr.
#
cmake_push_check_state()
if(WIN32)
    set(CMAKE_EXTRA_INCLUDE_FILES sys/types.h ws2tcpip.h)
    check_symbol_exists(AF_INET6 "sys/types.h;ws2tcpip.h" HAVE_AF_INET6)
else(WIN32)
    set(CMAKE_EXTRA_INCLUDE_FILES sys/types.h sys/socket.h netinet/in.h)
    check_symbol_exists(AF_INET6 "sys/types.h;sys/socket.h;netinet/in.h" HAVE_AF_INET6)
endif(WIN32)
check_type_size("struct in6_addr" HAVE_STRUCT_IN6_ADDR)
cmake_pop_check_state()
if(HAVE_AF_INET6 AND HAVE_STRUCT_IN6_ADDR)
    set(HAVE_OS_IPV6_SUPPORT TRUE)
endif(HAVE_AF_INET6 AND HAVE_STRUCT_IN6_ADDR)

#
# Structure fields.
#
check_struct_has_member("struct sockaddr" sa_len sys/socket.h HAVE_SOCKADDR_SA_LEN)

######################################
# External dependencies
######################################

include(CheckLibraryExists)

#
# libpcap/WinPcap.
# First find it, then check for functions in it.
#
find_package(PCAP REQUIRED)

#
# Check for various functions in libpcap/WinPcap.
#
include_directories(${PCAP_INCLUDE_DIR})
cmake_push_check_state()
set(CMAKE_REQUIRED_LIBRARIES ${PCAP_LIBRARY})

#
# Check for "pcap_list_datalinks()" and use a substitute version if
# it's not present.  If it is present, check for "pcap_free_datalinks()";
# if it's not present, we don't replace it for now.  (We could do so
# on UN*X, but not on Windows, where hilarity ensues if a program
# built with one version of the MSVC support library tries to free
# something allocated by a library built with another version of
# the MSVC support library.)
#
check_function_exists(pcap_list_datalinks HAVE_PCAP_LIST_DATALINKS)
if(HAVE_PCAP_LIST_DATALINKS)
    check_function_exists(pcap_free_datalinks HAVE_PCAP_FREE_DATALINKS)
endif(HAVE_PCAP_LIST_DATALINKS)

#
# Check for "pcap_datalink_name_to_val()", and use a substitute
# version if it's not present.  If it is present, check for
# "pcap_datalink_val_to_description()", and if we don't have it,
# use a substitute version.
#
check_function_exists(pcap_datalink_name_to_val HAVE_PCAP_DATALINK_NAME_TO_VAL)
if(HAVE_PCAP_DATALINK_NAME_TO_VAL)
    check_function_exists(pcap_datalink_val_to_description HAVE_PCAP_DATALINK_VAL_TO_DESCRIPTION)
endif(HAVE_PCAP_DATALINK_NAME_TO_VAL)

#
# Check for "pcap_set_datalink()"; you can't substitute for it if
# it's absent (it has hooks into libpcap), so just define the
# HAVE_ value if it's there.
#
check_function_exists(pcap_set_datalink HAVE_PCAP_SET_DATALINK)

#
# Check for "pcap_breakloop()"; you can't substitute for it if
# it's absent (it has hooks into the live capture routines),
# so just define the HAVE_ value if it's there.
#
check_function_exists(pcap_breakloop HAVE_PCAP_BREAKLOOP)

#
# Check for "pcap_dump_ftell()"; we use a substitute version
# if it's not present.
#
check_function_exists(pcap_dump_ftell HAVE_PCAP_DUMP_FTELL)

#
# Do we have the new open API?  Check for pcap_create, and assume that,
# if we do, we also have pcap_activate() and the other new routines
# introduced in libpcap 1.0.0.
#
check_function_exists(pcap_create HAVE_PCAP_CREATE)
if(HAVE_PCAP_CREATE)
    #
    # OK, do we have pcap_set_tstamp_type?  If so, assume we have
    # pcap_list_tstamp_types and pcap_free_tstamp_types as well.
    #
    check_function_exists(pcap_set_tstamp_type HAVE_PCAP_SET_TSTAMP_TYPE)

    #
    # And do we have pcap_set_tstamp_precision?  If so, we assume
    # we also have pcap_open_offline_with_tstamp_precision.
    #
    check_function_exists(pcap_set_tstamp_precision HAVE_PCAP_SET_TSTAMP_PRECISION)
endif(HAVE_PCAP_CREATE)

#
# Check for a miscellaneous collection of functions which we use
# if we have them.
#
check_function_exists(pcap_findalldevs HAVE_PCAP_FINDALLDEVS)
if(HAVE_PCAP_FINDALLDEVS)
    #
    # Check for libpcap having pcap_findalldevs() but the pcap.h header
    # not having pcap_if_t; some versions of Mac OS X shipped with pcap.h
    # from 0.6 and libpcap 0.8, so that libpcap had pcap_findalldevs but
    # pcap.h didn't have pcap_if_t.
    #
    cmake_push_check_state()
    set(CMAKE_EXTRA_INCLUDE_FILES pcap.h)
    check_type_size(pcap_if_t PCAP_IF_T)
    cmake_pop_check_state()
endif(HAVE_PCAP_FINDALLDEVS)
check_function_exists(pcap_dump_flush HAVE_PCAP_DUMP_FLUSH)
check_function_exists(pcap_lib_version HAVE_PCAP_LIB_VERSION)
if(NOT HAVE_PCAP_LIB_VERSION)
    # Check for the pcap_version string variable and set HAVE_PCAP_VERSION
endif(NOT HAVE_PCAP_LIB_VERSION)
check_function_exists(pcap_setdirection HAVE_PCAP_SETDIRECTION)
check_function_exists(pcap_set_immediate_mode HAVE_PCAP_SET_IMMEDIATE_MODE)
check_function_exists(pcap_dump_ftell64 HAVE_PCAP_DUMP_FTELL64)
check_function_exists(pcap_open HAVE_PCAP_OPEN)
check_function_exists(pcap_findalldevs_ex HAVE_PCAP_FINDALLDEVS_EX)

#
# Check for special debugging functions
#
check_function_exists(pcap_set_parser_debug HAVE_PCAP_SET_PARSER_DEBUG)
if(NOT HAVE_PCAP_SET_PARSER_DEBUG)
    # Check whether libpcap defines pcap_debug or yydebug
endif(NOT HAVE_PCAP_SET_PARSER_DEBUG)

check_function_exists(pcap_set_optimizer_debug HAVE_PCAP_SET_OPTIMIZER_DEBUG)
check_function_exists(bpf_dump HAVE_BPF_DUMP)

cmake_pop_check_state()

#
# We have libpcap.
#
include_directories(SYSTEM ${PCAP_INCLUDE_DIRS})
set(TCPDUMP_LINK_LIBRARIES ${PCAP_LIBRARY})

#
# Optional libraries.
#
#
# libsmi.
#
if(WITH_SMI)
    find_package(SMI)
    if(SMI_FOUND)
        include_directories(SYSTEM ${SMI_INCLUDE_DIRS})
        set(TCPDUMP_LINK_LIBRARIES ${TCPDUMP_LINK_LIBRARIES} ${SMI_LIBRARY})
        set(USE_LIBSMI ON)
    endif(SMI_FOUND)
endif(WITH_SMI)

#
# OpenSSL/libressl libcrypto.
#
if(WITH_CRYPTO)
    find_package(CRYPTO)
    if(CRYPTO_FOUND)
        #
        # Check for some functions.
        #
        cmake_push_check_state()
        set(CMAKE_REQUIRED_LIBRARIES crypto)

        #
      	# 1) do we have EVP_CIPHER_CTX_new?
        # If so, we use it to allocate an EVP_CIPHER_CTX, as
        # EVP_CIPHER_CTX may be opaque; otherwise, we allocate
        # it ourselves.
        #
        check_function_exists(EVP_CIPHER_CTX_new HAVE_EVP_CIPHER_CTX_NEW)

        #
        # 2) do we have EVP_CipherInit_ex()?
        # If so, we use it, because we need to be able to make two
        # "initialize the cipher" calls, one with the cipher and key,
        # and one with the IV, and, as of OpenSSL 1.1, You Can't Do That
        # with EVP_CipherInit(), because a call to EVP_CipherInit() will
        # unconditionally clear the context, and if you don't supply a
        # cipher, it'll clear the cipher, rendering the context unusable
        # and causing a crash.
        #
        check_function_exists(EVP_CipherInit_ex HAVE_EVP_CIPHERINIT_EX)

        cmake_pop_check_state()

        #
        # We have libcrypto.
        #
        include_directories(SYSTEM ${CRYPTO_INCLUDE_DIRS})
        set(TCPDUMP_LINK_LIBRARIES ${TCPDUMP_LINK_LIBRARIES} ${CRYPTO_LIBRARY})
        set(HAVE_LIBCRYPTO ON)
    endif(CRYPTO_FOUND)
endif(WITH_CRYPTO)

#
# Capsicum sandboxing.
# Some of this is in the system library, some of it is in other libraries.
#
if(WITH_CAPSICUM)
    check_function_exists(cap_enter HAVE_CAP_ENTER)
    check_function_exists(cap_rights_limit HAVE_CAP_RIGHTS_LIMIT)
    check_function_exists(cap_ioctls_limit HAVE_CAP_IOCTLS_LIMIT)
    check_function_exists(openat HAVE_OPENAT)
    if(HAVE_CAP_ENTER AND HAVE_CAP_RIGHTS_LIMIT AND
       HAVE_CAP_IOCTLS_LIMIT AND HAVE_OPENAT)
        #
        # OK, we have the functions we need to support Capsicum.
        #
        set(HAVE_CAPSICUM TRUE)

        #
        # OK, can we use Casper?
        #
        check_library_exists(casper cap_init "" HAVE_CAP_INIT)
        if(HAVE_CAP_INIT)
            cmake_push_check_state()
            set(CMAKE_REQUIRED_LIBRARIES casper)
            check_library_exists(cap_dns cap_gethostbyaddr "" HAVE_CAP_GETHOSTBYADDR)
            cmake_pop_check_state()
            if(HAVE_CAP_GETHOSTBYADDR)
                set(HAVE_CASPER TRUE)
                set(TCPDUMP_LINK_LIBRARIES ${TCPDUMP_LINK_LIBRARIES} casper cap_dns)
            endif(HAVE_CAP_GETHOSTBYADDR)
        endif(HAVE_CAP_INIT)
    endif(HAVE_CAP_ENTER AND HAVE_CAP_RIGHTS_LIMIT AND
          HAVE_CAP_IOCTLS_LIMIT AND HAVE_OPENAT)
endif(WITH_CAPSICUM)

#
# libcap-ng.
#
if(WITH_CAP_NG)
    check_include_file(cap-ng.h HAVE_CAP_NG_H)
    check_library_exists(cap-ng capng_change_id "" HAVE_LIBCAP_NG)
    if(HAVE_LIBCAP_NG)
        set(TCPDUMP_LINK_LIBRARIES ${TCPDUMP_LINK_LIBRARIES} cap-ng)
    endif(HAVE_LIBCAP_NG)
endif(WITH_CAP_NG)

######################################
# Input files
######################################

if(ENABLE_SMB)
    #
    # We allow the SMB dissector to be omitted.
    #
    set(LOCALSRC ${LOCALSRC}
        print-smb.c
        smbutil.c)
endif(ENABLE_SMB)

set(NETDISSECT_SOURCE_LIST_C
    addrtoname.c
    addrtostr.c
    af.c
    ascii_strcasecmp.c
    checksum.c
    cpack.c
    gmpls.c
    gmt2local.c
    in_cksum.c
    ipproto.c
    l2vpn.c
    machdep.c
    nlpid.c
    oui.c
    parsenfsfh.c
    print.c
    print-802_11.c
    print-802_15_4.c
    print-ah.c
    print-ahcp.c
    print-aodv.c
    print-aoe.c
    print-ap1394.c
    print-arcnet.c
    print-arp.c
    print-ascii.c
    print-atalk.c
    print-atm.c
    print-babel.c
    print-beep.c
    print-bfd.c
    print-bgp.c
    print-bootp.c
    print-bt.c
    print-calm-fast.c
    print-carp.c
    print-cdp.c
    print-cfm.c
    print-chdlc.c
    print-cip.c
    print-cnfp.c
    print-dccp.c
    print-decnet.c
    print-dhcp6.c
    print-domain.c
    print-dtp.c
    print-dvmrp.c
    print-eap.c
    print-egp.c
    print-eigrp.c
    print-enc.c
    print-esp.c
    print-ether.c
    print-fddi.c
    print-forces.c
    print-fr.c
    print-frag6.c
    print-ftp.c
    print-geneve.c
    print-geonet.c
    print-gre.c
    print-hncp.c
    print-hsrp.c
    print-http.c
    print-icmp.c
    print-icmp6.c
    print-igmp.c
    print-igrp.c
    print-ip.c
    print-ip6.c
    print-ip6opts.c
    print-ipcomp.c
    print-ipfc.c
    print-ipnet.c
    print-ipx.c
    print-isakmp.c
    print-isoclns.c
    print-juniper.c
    print-krb.c
    print-l2tp.c
    print-lane.c
    print-ldp.c
    print-lisp.c
    print-llc.c
    print-lldp.c
    print-lmp.c
    print-loopback.c
    print-lspping.c
    print-lwapp.c
    print-lwres.c
    print-m3ua.c
    print-medsa.c
    print-mobile.c
    print-mobility.c
    print-mpcp.c
    print-mpls.c
    print-mptcp.c
    print-msdp.c
    print-msnlb.c
    print-nflog.c
    print-nfs.c
    print-nsh.c
    print-ntp.c
    print-null.c
    print-olsr.c
    print-openflow-1.0.c
    print-openflow.c
    print-ospf.c
    print-ospf6.c
    print-otv.c
    print-pgm.c
    print-pim.c
    print-pktap.c
    print-ppi.c
    print-ppp.c
    print-pppoe.c
    print-pptp.c
    print-radius.c
    print-raw.c
    print-resp.c
    print-rip.c
    print-ripng.c
    print-rpki-rtr.c
    print-rrcp.c
    print-rsvp.c
    print-rt6.c
    print-rtsp.c
    print-rx.c
    print-sctp.c
    print-sflow.c
    print-sip.c
    print-sl.c
    print-sll.c
    print-slow.c
    print-smtp.c
    print-snmp.c
    print-stp.c
    print-sunatm.c
    print-sunrpc.c
    print-symantec.c
    print-syslog.c
    print-tcp.c
    print-telnet.c
    print-tftp.c
    print-timed.c
    print-tipc.c
    print-token.c
    print-udld.c
    print-udp.c
    print-usb.c
    print-vjc.c
    print-vqp.c
    print-vrrp.c
    print-vtp.c
    print-vxlan.c
    print-vxlan-gpe.c
    print-wb.c
    print-zephyr.c
    print-zeromq.c
    ${LOCALSRC}
    netdissect.c
    signature.c
    strtoaddr.c
    util-print.c
)

#
# Replace missing functions
#
foreach(FUNC strlcat strlcpy strdup strsep getservent getopt_long)
    string(TOUPPER ${FUNC} FUNC_UPPERCASE)
    set(HAVE_FUNC_UPPERCASE HAVE_${FUNC_UPPERCASE})
    if(NOT ${HAVE_FUNC_UPPERCASE})
        set(NETDISSECT_SOURCE_LIST_C ${NETDISSECT_SOURCE_LIST_C} missing/${FUNC}.c)
    endif()
endforeach()
if(NOT HAVE_VSNPRINTF OR NOT HAVE_SNPRINTF)
    set(NETDISSECT_SOURCE_LIST_C ${NETDISSECT_SOURCE_LIST_C} missing/snprintf.c)
endif(NOT HAVE_VSNPRINTF OR NOT HAVE_SNPRINTF)

add_library(netdissect STATIC
    ${NETDISSECT_SOURCE_LIST_C}
)

set(TCPDUMP_SOURCE_LIST_C tcpdump.c)

if(NOT HAVE_BPF_DUMP)
    set(TCPDUMP_SOURCE_LIST_C ${TCPDUMP_SOURCE_LIST_C} bpf_dump.c)
endif(NOT HAVE_BPF_DUMP)
if(NOT HAVE_PCAP_DUMP_FTELL)
    set(TCPDUMP_SOURCE_LIST_C ${TCPDUMP_SOURCE_LIST_C} missing/pcap_dump_ftell.c)
endif(NOT HAVE_PCAP_DUMP_FTELL)

if(NOT HAVE_PCAP_LIST_DATALINKS)
    set(TCPDUMP_SOURCE_LIST_C ${TCPDUMP_SOURCE_LIST_C} missing/datalinks.c)
endif(NOT HAVE_PCAP_LIST_DATALINKS)

if((NOT HAVE_PCAP_DATALINK_NAME_TO_VAL) OR (NOT HAVE_PCAP_DATALINK_VAL_TO_DESCRIPTION))
    set(TCPDUMP_SOURCE_LIST_C ${TCPDUMP_SOURCE_LIST_C} missing/dlnames.c)
endif((NOT HAVE_PCAP_DATALINK_NAME_TO_VAL) OR (NOT HAVE_PCAP_DATALINK_VAL_TO_DESCRIPTION))

set(PROJECT_SOURCE_LIST_C ${NETDISSECT_SOURCE_LIST_C} ${TCPDUMP_SOURCE_LIST_C})

file(GLOB PROJECT_SOURCE_LIST_H
    *.h
)

source_group("Source Files" FILES ${PROJECT_SOURCE_LIST_C})
source_group("Header Files" FILES ${PROJECT_SOURCE_LIST_H})

######################################
# Register targets
######################################

add_executable(tcpdump ${TCPDUMP_SOURCE_LIST_C})
target_link_libraries(tcpdump netdissect ${TCPDUMP_LINK_LIBRARIES})

######################################
# Write out the config.h file
######################################

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/cmakeconfig.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

######################################
# Install tcpdump and man pages
######################################

#
# "Define GNU standard installation directories", which actually
# are also defined, to some degree, by autotools, and at least
# some of which are general UN*X conventions.
#
include(GNUInstallDirs)

set(MAN1_EXPAND tcpdump.1.in)

if(WIN32)
    # XXX TODO where to install on Windows?
else(WIN32)
    install(TARGETS tcpdump DESTINATION sbin)
endif(WIN32)

# On UN*X, and on Windows when not using MSVC, process man pages and
# arrange that they be installed.
if(NOT MSVC)
    #
    # Man pages.
    #
    # For each section of the manual for which we have man pages
    # that require macro expansion, do the expansion.
    #
    set(MAN1 "")
    foreach(TEMPLATE_MANPAGE ${MAN1_EXPAND})
        string(REPLACE ".in" "" MANPAGE ${TEMPLATE_MANPAGE})
        configure_file(${CMAKE_SOURCE_DIR}/${TEMPLATE_MANPAGE} ${CMAKE_CURRENT_BINARY_DIR}/${MANPAGE} @ONLY)
        set(MAN1 ${MAN1} ${CMAKE_CURRENT_BINARY_DIR}/${MANPAGE})
    endforeach(TEMPLATE_MANPAGE)
    install(FILES ${MAN1} DESTINATION ${CMAKE_INSTALL_MANDIR}/man1)
endif(NOT MSVC)

# uninstall target
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
    IMMEDIATE @ONLY)

add_custom_target(uninstall
    COMMAND ${CMAKE_COMMAND} -P ${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake)
