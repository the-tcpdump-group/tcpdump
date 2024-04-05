# Compiling tcpdump on Solaris and related OSes

* Autoconf works everywhere.

## OmniOS r151048/AMD64

* Both system and local libpcap are suitable.
* CMake 3.29.0 works
* GCC 13.2.0 and Clang 17.0.6 work.

## OmniOS r151046/AMD64

* Both system and local libpcap are suitable.
* CMake 3.26.4 works
* GCC 12.2.0 and Clang 16.0.4 work.

## OmniOS r151044/AMD64

* Both system and local libpcap are suitable.
* CMake 3.25.2 works.
* GCC 12.2.0 and Clang 15.0.7 work.

## OmniOS r151042/AMD64

* Both system and local libpcap are suitable.
* CMake 3.23.1 works.
* GCC 11.2.0 and Clang 14.0.3 work.

## OpenIndiana 2023.10/AMD64

* Both system and local libpcap are suitable.
* CMake 3.29.0 works
* GCC 13.2.0 and Clang 17.0.6 work.

## OpenIndiana 2021.04/AMD64

* Both system and local libpcap are suitable.
* CMake 3.21.1 works.
* GCC 7.5.0 and GCC 10.3.0 work, Clang 9.0.1 works.

For reference, the tests were done using a system installed from
`OI-hipster-text-20210430.iso` plus the following packages:
```shell
xargs -L1 pkg install <<ENDOFTEXT
developer/build/autoconf
developer/build/cmake
developer/gcc-10
developer/clang-90
ENDOFTEXT
```

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
