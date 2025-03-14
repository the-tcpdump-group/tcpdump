#!/bin/sh -e

: "${AUTORECONF:=autoreconf}"
: "${BUILD_YEAR2038:=no}"

AUTORECONFVERSION=`$AUTORECONF --version 2>&1 | grep "^autoreconf" | sed 's/.*) *//'`

maj=`echo "$AUTORECONFVERSION" | cut -d. -f1`
min=`echo "$AUTORECONFVERSION" | cut -d. -f2`
# The minimum required version of autoconf is currently 2.69.
if [ "$maj" = "" ] || [ "$min" = "" ] || \
   [ "$maj" -lt 2 ] || { [ "$maj" -eq 2 ] && [ "$min" -lt 69 ]; }; then
	cat >&2 <<-EOF
	Please install the 'autoconf' package version 2.69 or later.
	If version 2.69 or later is already installed and there is no
	autoconf default, it may be necessary to set the AUTORECONF
	environment variable to enable the one to use, like:
	AUTORECONF=autoreconf-2.69 ./autogen.sh
	or
	AUTORECONF=autoreconf-2.71 ./autogen.sh
	EOF
	exit 1
fi

# On Linux, if Autoconf version >= 2.72 and GNU C Library version >= 2.34,
# s/AC_SYS_LARGEFILE/AC_SYS_YEAR2038_RECOMMENDED/ to ensure time_t
# is Y2038-safe.
if [ "$BUILD_YEAR2038" = yes ] && [ "`uname -s`" = Linux ]; then
	if [ "$maj" -gt 2 ] || { [ "$maj" -eq 2 ] && [ "$min" -ge 72 ]; }; then
		GLIBC_VERSION=`ldd --version|head -1|grep GLIBC|sed 's/.* //'`
		maj_glibc=`echo "$GLIBC_VERSION" | cut -d. -f1`
		min_glibc=`echo "$GLIBC_VERSION" | cut -d. -f2`
		if [ "$maj_glibc" -gt 2 ] || { [ "$maj_glibc" -eq 2 ] && \
		   [ "$min_glibc" -ge 34 ]; }; then
			CONFIGURE_AC_NEW="configure.ac.new$$"
			sed 's/^# \(AC_SYS_YEAR2038_RECOMMENDED\)/\1/' \
				<configure.ac >"$CONFIGURE_AC_NEW"
			cmp -s configure.ac "$CONFIGURE_AC_NEW" || \
			cat "$CONFIGURE_AC_NEW" >configure.ac
			rm -f "$CONFIGURE_AC_NEW"
			echo 'Setup to ensure time_t is Y2038-safe.'
		fi
	fi
fi

echo "$AUTORECONF identification: $AUTORECONFVERSION"
"$AUTORECONF" -f
