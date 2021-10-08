# Compiling tcpdump on Solaris and related OSes

* Autoconf works everywhere.

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
