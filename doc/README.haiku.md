# Compiling tcpdump on Haiku

## AMD64 R1/beta5

* Both HaikuPorts and local libpcap are suitable.
* Autoconf 2.72 works.
* CMake 3.28.3 works.
* GCC 13.3.0 works.
* Clang 18.1.7 works.

The following command will install respective non-default packages:
```
pkgman install libpcap_devel cmake llvm18_clang
```

For reference, the tests were done using a system installed from
`haiku-r1beta5-x86_64-anyboot.iso`.
