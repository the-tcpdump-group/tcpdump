# tcpdump installation notes

## Installing libpcap

Tcpdump requires libpcap.

### On UN*Xes

Your system might provide a version of libpcap that can be installed, or
that is installed by default; if so, to compile tcpdump you might need
to install a "developer" version of libpcap as well as the "run-time"
version, even if the "run-time" version has already been installed.

If your system does not provide libpcap, or provides a version that does
not support all of the libpcap 1.0 APIs, you will need to download the
source for The Tcpdump Group version of libpcap; see [this
file](README.md) for the location, and build and install that version.
Either install libpcap with `make install` or make sure both the libpcap
and tcpdump source trees are in the same directory.

### On Windows

You will need to install both Npcap and the Npcap SDK; see [this
file](doc/README.windows.md) for information on that.

## Building tcpdump

You will need a C99 compiler to build tcpdump and, if necessary, to
build libpcap.  The build system will abort if your compiler is not C99
compliant.  If this happens, use the generally available GNU C compiler
(GCC) or Clang.

Once you have a version of libpcap with which you can build tcpdump, do
the following steps:

* If you build from a git clone rather than from a release archive,
run `./autogen.sh` (a shell script). The autogen.sh script will
build the `configure` and `config.h.in` files.

On some system, you may need to set the `AUTORECONF` variable, like:
`AUTORECONF=autoreconf-2.69 ./autogen.sh`
to select the `autoreconf` version you want to use.

* Run `./configure` (a shell script). The configure script will
determine your system attributes and generate an appropriate `Makefile`
from `Makefile.in`.  The configure script has a number of options to
control the configuration of tcpdump; `./configure --help` will show
them.

* Next, build tcpdump by running `make`.

On OpenBSD, you may need to set, before the `make`, the `AUTOCONF_VERSION`
variable like:
`AUTOCONF_VERSION=2.69 make`

If everything builds fine, `su` and type `make install`.  This will install
tcpdump and the manual entry.  Any user will be able to use tcpdump to
read saved captures.  Whether a user will be able to capture traffic
depends on the OS and the configuration of the system; see the
[tcpdump man page](https://www.tcpdump.org/manpages/tcpdump.1.html)
for details.  Do **NOT** give untrusted users the ability to
capture traffic.  If a user can capture traffic, he or she could use
utilities such as tcpdump to capture any traffic on your net, including
passwords.

Note that most systems ship tcpdump, but usually an older version.
Building tcpdump from source as explained above will usually install the
binary as `/usr/local/bin/tcpdump`.  If your system has other tcpdump
binaries, you might need to deinstall these or to set the `PATH` environment
variable if you need the `tcpdump` command to run the new binary
(`tcpdump --version` can be used to tell different versions apart).

If your system is not one that we have tested tcpdump on, you may have
to modify the `configure` script and `Makefile.in`. Please
[send us patches](https://www.tcpdump.org/index.html#patches)
for any modifications you need to make.

Please see [this file](README.md) for notes about tested platforms.


## Description of files
```
CHANGES		- description of differences between releases
CONTRIBUTING.md	- guidelines for contributing
CREDITS		- people that have helped tcpdump along
INSTALL.md	- this file
LICENSE		- the license under which tcpdump is distributed
Makefile.in	- compilation rules (input to the configure script)
README.md	- description of distribution
VERSION		- version of this release
aclocal.m4	- autoconf macros
addrtoname.c	- address to hostname routines
addrtoname.h	- address to hostname definitions
addrtostr.c	- address to printable string routines
addrtostr.h	- address to printable string definitions
ah.h		- IPSEC Authentication Header definitions
appletalk.h	- AppleTalk definitions
ascii_strcasecmp.c - locale-independent case-independent string comparison
		routines
atime.awk	- TCP ack awk script
atm.h		- ATM traffic type definitions
autogen.sh	- build configure and config.h.in (run this first)
bpf_dump.c	- BPF program printing routines, in case libpcap doesn't
		  have them. A known example is OpenBSD libpcap.
chdlc.h		- Cisco HDLC definitions
cpack.c		- functions to extract packed data
cpack.h		- declarations of functions to extract packed data
config.guess	- autoconf support
config.sub	- autoconf support
configure.ac	- configure script source
doc/README.*	- some building documentation
ethertype.h	- Ethernet type value definitions
extract.h	- alignment definitions
gmpls.c		- GMPLS definitions
gmpls.h		- GMPLS declarations
gre.h		- GRE definitions
install-sh	- BSD style install script
interface.h	- globals, prototypes and definitions
ip.h		- IP definitions
ip6.h		- IPv6 definitions
ipproto.c	- IP protocol type value-to-name table
ipproto.h	- IP protocol type value definitions
l2vpn.c		- L2VPN encapsulation value-to-name table
l2vpn.h		- L2VPN encapsulation definitions
lbl/os-*.h	- OS-dependent defines and prototypes (currently none)
llc.h		- LLC definitions
makemib		- mib to header script
mib.h		- mib definitions
missing/*	- replacements for missing library functions
ntp.c		- functions to handle ntp structs
ntp.h		- declarations of functions to handle ntp structs
mkdep		- construct Makefile dependency list
mpls.h		- MPLS definitions
nameser.h	- DNS definitions
netdissect.h	- definitions and declarations for tcpdump-as-library
		  (under development)
nfs.h		- Network File System V2 definitions
nfsfh.h		- Network File System file handle definitions
nlpid.c		- OSI NLPID value-to-name table
nlpid.h		- OSI NLPID definitions
ospf.h		- Open Shortest Path First definitions
packetdat.awk	- TCP chunk summary awk script
parsenfsfh.c	- Network File System file parser routines
ppp.h		- Point to Point Protocol definitions
print.c		- Top-level routines for protocol printing
print-*.c	- The netdissect printers
rpc_auth.h	- definitions for ONC RPC authentication
rpc_msg.h	- definitions for ONC RPC messages
send-ack.awk	- unidirectional tcp send/ack awk script
slcompress.h	- SLIP/PPP Van Jacobson compression (RFC1144) definitions
smb.h		- SMB/CIFS definitions
smbutil.c	- SMB/CIFS utility routines
stime.awk	- TCP send awk script
tcp.h		- TCP definitions
tcpdump.1	- manual entry
tcpdump.c	- main program
timeval-operations.h - timeval operations macros
udp.h		- UDP definitions
util-print.c	- utility routines for protocol printers
```
