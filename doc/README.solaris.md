# Compiling tcpdump on Solaris and related OSes

* Autoconf works everywhere.

## OmniOS r151054/AMD64

* Both system and local libpcap are suitable.
* CMake 4.0.1 works.
* GCC 14.2.0 and Clang 20.1.2 work.

## OmniOS r151052/AMD64

* Both system and local libpcap are suitable.
* CMake 3.30.5 works.
* GCC 14.2.0 and Clang 19.1.2 work.

## OmniOS r151046/AMD64

* Both system and local libpcap are suitable.
* CMake 3.26.4 works
* GCC 12.2.0 and Clang 16.0.4 work.

## OpenIndiana 2023.10/AMD64

* Both system and local libpcap are suitable.
* CMake 3.29.0 works
* GCC 13.2.0 and Clang 17.0.6 work.

## Oracle Solaris CBE (11.4.42.111.0)/AMD64

* Both system and local libpcap are suitable.
* CMake 3.21.0 works.
* GCC 11.2 and Clang 11.0 work.
* Sun C 5.15 works.

For reference, the tests were done using the following packages:
```shell
xargs -L1 pkg install <<ENDOFTEXT
developer/build/autoconf
developer/build/cmake
developer/gcc
developer/llvm/clang
ENDOFTEXT
```

## Solaris 11.3/(SPARC and AMD64)

* Both system and local libpcap are suitable.
* CMake 3.14.3 works.
* Sun C 5.13 and GCC 5.5.0 work.

## Solaris 10/SPARC

* Both system and local libpcap are suitable.
* CMake 3.14.3 works.
* Sun C 5.9 and GCC 5.5.0 work.

## Solaris 9

This version of this OS is not supported because the snprintf(3) implementation
in its libc is not suitable.
