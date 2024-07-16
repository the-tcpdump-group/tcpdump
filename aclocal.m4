dnl Copyright (c) 1995, 1996, 1997, 1998
dnl	The Regents of the University of California.  All rights reserved.
dnl
dnl Redistribution and use in source and binary forms, with or without
dnl modification, are permitted provided that: (1) source code distributions
dnl retain the above copyright notice and this paragraph in its entirety, (2)
dnl distributions including binary code include the above copyright notice and
dnl this paragraph in its entirety in the documentation or other materials
dnl provided with the distribution, and (3) all advertising materials mentioning
dnl features or use of this software display the following acknowledgement:
dnl ``This product includes software developed by the University of California,
dnl Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
dnl the University nor the names of its contributors may be used to endorse
dnl or promote products derived from this software without specific prior
dnl written permission.
dnl THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
dnl WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
dnl MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
dnl
dnl LBL autoconf macros
dnl

dnl
dnl Do whatever AC_LBL_C_INIT work is necessary before using AC_PROG_CC.
dnl
dnl It appears that newer versions of autoconf (2.64 and later) will,
dnl if you use AC_TRY_COMPILE in a macro, stick AC_PROG_CC at the
dnl beginning of the macro, even if the macro itself calls AC_PROG_CC.
dnl See the "Prerequisite Macros" and "Expanded Before Required" sections
dnl in the Autoconf documentation.
dnl
dnl This causes a steaming heap of fail in our case, as we were, in
dnl AC_LBL_C_INIT, doing the tests we now do in AC_LBL_C_INIT_BEFORE_CC,
dnl calling AC_PROG_CC, and then doing the tests we now do in
dnl AC_LBL_C_INIT.  Now, we run AC_LBL_C_INIT_BEFORE_CC, AC_PROG_CC,
dnl and AC_LBL_C_INIT at the top level.
dnl
AC_DEFUN(AC_LBL_C_INIT_BEFORE_CC,
[
    AC_BEFORE([$0], [AC_LBL_C_INIT])
    AC_BEFORE([$0], [AC_PROG_CC])
    AC_BEFORE([$0], [AC_LBL_DEVEL])
    AC_ARG_WITH(gcc, [  --without-gcc           don't use gcc])
    $1=""
    if test "${srcdir}" != "." ; then
	    $1="-I$srcdir"
    fi
    if test "${CFLAGS+set}" = set; then
	    LBL_CFLAGS="$CFLAGS"
    fi
    if test -z "$CC" -a "$with_gcc" = no ; then
	    CC=cc
	    export CC
    fi
])

dnl
dnl Determine which compiler we're using (cc or gcc)
dnl If using gcc, determine the version number
dnl If using cc:
dnl     require that it support ansi prototypes
dnl     use -O (AC_PROG_CC will use -g -O2 on gcc, so we don't need to
dnl     do that ourselves for gcc)
dnl     add -g flags, as appropriate
dnl     explicitly specify /usr/local/include
dnl
dnl NOTE WELL: with newer versions of autoconf, "gcc" means any compiler
dnl that defines __GNUC__, which means clang, for example, counts as "gcc".
dnl
dnl usage:
dnl
dnl	AC_LBL_C_INIT(copt, incls)
dnl
dnl results:
dnl
dnl	$1 (copt set)
dnl	$2 (incls set)
dnl	CC
dnl	LDFLAGS
dnl	LBL_CFLAGS
dnl
AC_DEFUN(AC_LBL_C_INIT,
[
    AC_BEFORE([$0], [AC_LBL_DEVEL])
    if test "$GCC" = yes ; then
	    #
	    # -Werror forces warnings to be errors.
	    #
	    ac_lbl_cc_force_warning_errors=-Werror
    else
	    $2="$$2 -I/usr/local/include"
	    LDFLAGS="$LDFLAGS -L/usr/local/lib"

	    case "$host_os" in

	    darwin*)
		    #
		    # This is assumed either to be GCC or clang, both
		    # of which use -Werror to force warnings to be errors.
		    #
		    # XXX - they also both cause GCC to be set to yes,
		    # so we should never get here in the first place.
		    #
		    ac_lbl_cc_force_warning_errors=-Werror
		    ;;

	    hpux*)
		    #
		    # HP C, which is what we presume we're using, doesn't
		    # exit with a non-zero exit status if we hand it an
		    # invalid -W flag, can't be forced to do so even with
		    # +We, and doesn't handle GCC-style -W flags, so we
		    # don't want to try using GCC-style -W flags.
		    #
		    ac_lbl_cc_dont_try_gcc_dashW=yes
		    ;;

	    solaris*)
		    #
		    # Assumed to be Sun C, which requires -errwarn to force
		    # warnings to be treated as errors.
		    #
		    ac_lbl_cc_force_warning_errors=-errwarn
		    ;;
	    esac
	    $1="$$1 -O"
    fi
])

dnl
dnl Save the values of various variables that affect compilation and
dnl linking, and that we don't ourselves modify persistently; done
dnl before a test involving compiling or linking is done, so that we
dnl can restore those variables after the test is done.
dnl
AC_DEFUN(AC_LBL_SAVE_CHECK_STATE,
[
	save_CFLAGS="$CFLAGS"
	save_LIBS="$LIBS"
	save_LDFLAGS="$LDFLAGS"
])

dnl
dnl Restore the values of variables saved by AC_LBL_SAVE_CHECK_STATE.
dnl
AC_DEFUN(AC_LBL_RESTORE_CHECK_STATE,
[
	CFLAGS="$save_CFLAGS"
	LIBS="$save_LIBS"
	LDFLAGS="$save_LDFLAGS"
])

dnl
dnl Check whether the compiler option specified as the second argument
dnl is supported by the compiler and, if so, add it to the macro
dnl specified as the first argument
dnl
AC_DEFUN(AC_LBL_CHECK_COMPILER_OPT,
    [
	AC_MSG_CHECKING([whether the compiler supports the $2 option])
	save_CFLAGS="$CFLAGS"
	CFLAGS="$CFLAGS $2"
	#
	# XXX - yes, this depends on the way AC_LANG_WERROR works,
	# but no mechanism is provided to turn AC_LANG_WERROR on
	# *and then turn it back off*, so that we *only* do it when
	# testing compiler options - 15 years after somebody asked
	# for it:
	#
	#     https://autoconf.gnu.narkive.com/gTAVmfKD/how-to-cancel-flags-set-by-ac-lang-werror
	#
	save_ac_c_werror_flag="$ac_c_werror_flag"
	ac_c_werror_flag=yes
	#
	# We use AC_LANG_SOURCE() so that we can control the complete
	# content of the program being compiled.  We do not, for example,
	# want the default "int main()" that AC_LANG_PROGRAM() generates,
	# as it will generate a warning with -Wold-style-definition, meaning
	# that we would treat it as not working, as the test will fail if
	# *any* error output, including a warning due to the flag we're
	# testing, is generated; see
	#
	#    https://www.postgresql.org/message-id/2192993.1591682589%40sss.pgh.pa.us
	#    https://www.postgresql.org/message-id/2192993.1591682589%40sss.pgh.pa.us
	#
	# This may, as per those two messages, be fixed in autoconf 2.70,
	# but we only require 2.69 or newer for now.
	#
	AC_COMPILE_IFELSE(
	    [AC_LANG_SOURCE([[int main(void) { return 0; }]])],
	    [
		AC_MSG_RESULT([yes])
		CFLAGS="$save_CFLAGS"
		$1="$$1 $2"
	    ],
	    [
		AC_MSG_RESULT([no])
		CFLAGS="$save_CFLAGS"
	    ])
	ac_c_werror_flag="$save_ac_c_werror_flag"
    ])

dnl
dnl Check whether the compiler supports an option to generate
dnl Makefile-style dependency lines
dnl
dnl GCC uses -M for this.  Non-GCC compilers that support this
dnl use a variety of flags, including but not limited to -M.
dnl
dnl We test whether the flag in question is supported, as older
dnl versions of compilers might not support it.
dnl
dnl We don't try all the possible flags, just in case some flag means
dnl "generate dependencies" on one compiler but means something else
dnl on another compiler.
dnl
dnl Most compilers that support this send the output to the standard
dnl output by default.  IBM's XLC, however, supports -M but sends
dnl the output to {sourcefile-basename}.u, and AIX has no /dev/stdout
dnl to work around that, so we don't bother with XLC.
dnl
AC_DEFUN(AC_LBL_CHECK_DEPENDENCY_GENERATION_OPT,
    [
	AC_MSG_CHECKING([whether the compiler supports generating dependencies])
	if test "$GCC" = yes ; then
		#
		# GCC, or a compiler deemed to be GCC by AC_PROG_CC (even
		# though it's not); we assume that, in this case, the flag
		# would be -M.
		#
		ac_lbl_dependency_flag="-M"
	else
		#
		# Not GCC or a compiler deemed to be GCC; what platform is
		# this?  (We're assuming that if the compiler isn't GCC
		# it's the compiler from the vendor of the OS; that won't
		# necessarily be true for x86 platforms, where it might be
		# the Intel C compiler.)
		#
		case "$host_os" in

		darwin*)
			#
			# Clang uses -M.
			#
			ac_lbl_dependency_flag="-M"
			;;

		solaris*)
			#
			# Sun C uses -xM.
			#
			ac_lbl_dependency_flag="-xM"
			;;

		hpux*)
			#
			# HP's older C compilers don't support this.
			# HP's newer C compilers support this with
			# either +M or +Make; the older compilers
			# interpret +M as something completely
			# different, so we use +Make so we don't
			# think it works with the older compilers.
			#
			ac_lbl_dependency_flag="+Make"
			;;

		*)
			#
			# Not one of the above; assume no support for
			# generating dependencies.
			#
			ac_lbl_dependency_flag=""
			;;
		esac
	fi

	#
	# Is ac_lbl_dependency_flag defined and, if so, does the compiler
	# complain about it?
	#
	# Note: clang doesn't seem to exit with an error status when handed
	# an unknown non-warning error, even if you pass it
	# -Werror=unknown-warning-option.  However, it always supports
	# -M, so the fact that this test always succeeds with clang
	# isn't an issue.
	#
	if test ! -z "$ac_lbl_dependency_flag"; then
		AC_LANG_CONFTEST(
		    [AC_LANG_SOURCE([[int main(void) { return 0; }]])])
		if AC_RUN_LOG([eval "$CC $ac_lbl_dependency_flag conftest.c >/dev/null 2>&1"]); then
			AC_MSG_RESULT([yes, with $ac_lbl_dependency_flag])
			DEPENDENCY_CFLAG="$ac_lbl_dependency_flag"
			MKDEP='${top_srcdir}/mkdep'
		else
			AC_MSG_RESULT([no])
			#
			# We can't run mkdep, so have "make depend" do
			# nothing.
			#
			MKDEP=:
		fi
		rm -rf conftest*
	else
		AC_MSG_RESULT([no])
		#
		# We can't run mkdep, so have "make depend" do
		# nothing.
		#
		MKDEP=:
	fi
	AC_SUBST(DEPENDENCY_CFLAG)
	AC_SUBST(MKDEP)
    ])

dnl
dnl Require libpcap
dnl Look for libpcap in directories under ..; those are local versions.
dnl Look for an installed libpcap if there is no local version or if
dnl the user said not to look for a local version.
dnl
dnl usage:
dnl
dnl	AC_LBL_LIBPCAP(pcapdep, incls)
dnl
dnl results:
dnl
dnl	$1 (pcapdep set)
dnl	$2 (incls appended)
dnl	LIBS
dnl
AC_DEFUN(AC_LBL_LIBPCAP,
[
    AC_REQUIRE([AC_PROG_EGREP])
    AC_REQUIRE([AC_LBL_LIBRARY_NET])
    libpcap=FAIL
    AC_MSG_CHECKING([whether to look for a local libpcap])
    AC_ARG_ENABLE(local-libpcap,
        AS_HELP_STRING([--disable-local-libpcap],
                       [don't look for a local libpcap @<:@default=check for a local libpcap@:>@]),,
        enableval=yes)
    case "$enableval" in

    no)
        AC_MSG_RESULT(no)
        #
        # Don't look for a local libpcap.
        #
        using_local_libpcap=no
        ;;

    *)
        AC_MSG_RESULT(yes)
        #
        # Look for a local pcap library.
        #
        AC_MSG_CHECKING(for local pcap library)
        lastdir=FAIL
        places=`ls $srcdir/.. | sed -e 's,/$,,' -e "s,^,$srcdir/../," | \
            $EGREP '/libpcap-[[0-9]]+\.[[0-9]]+(\.[[0-9]]*)?([[ab]][[0-9]]*|-PRE-GIT|rc.)?$'`
        places2=`ls .. | sed -e 's,/$,,' -e "s,^,../," | \
            $EGREP '/libpcap-[[0-9]]+\.[[0-9]]+(\.[[0-9]]*)?([[ab]][[0-9]]*|-PRE-GIT|rc.)?$'`
        for dir in $places $srcdir/../libpcap ../libpcap $srcdir/libpcap $places2 ; do
            basedir=`echo $dir | sed -e 's/[[ab]][[0-9]]*$//' | \
                sed -e 's/-PRE-GIT$//' `
            if test $lastdir = $basedir ; then
                dnl skip alphas when an actual release is present
                continue;
            fi
            lastdir=$dir
            if test -r $dir/libpcap.a ; then
                libpcap=$dir/libpcap.a
                local_pcap_dir=$dir
                dnl continue and select the last one that exists
            fi
        done
        if test $libpcap = FAIL ; then
            #
            # We didn't find a local libpcap.
            #
            AC_MSG_RESULT(not found)
            using_local_libpcap=no;
        else
            #
            # We found a local libpcap.
            #
            AC_MSG_RESULT($libpcap)
            using_local_libpcap=yes
        fi
        ;;
    esac

    if test $using_local_libpcap = no ; then
        #
        # We didn't find a local libpcap.
        # First, try finding it with pkg-config.
        #
        PKG_CHECK_MODULE(LIBPCAP, libpcap,
        [
            #
            # We found it; use the results as configuration information
            # for libpcap.
            #
            $2="$LIBPCAP_CFLAGS $$2"
            libpcap="$LIBPCAP_LIBS"
        ],
        [
            #
            # We didn't find it; look for an installed pcap-config.
            #
            AC_PATH_TOOL(PCAP_CONFIG, pcap-config)
            if test -n "$PCAP_CONFIG" ; then
                #
                # Found - use it to get the include flags for
                # libpcap and the flags to link with libpcap.
                #
                # If this is a vendor-supplied pcap-config, which
                # we define as being "a pcap-config in /usr/bin
                # or /usr/ccs/bin" (the latter is for Solaris and
                # Sun/Oracle Studio), there are some issues.  Work
                # around them.
                #
                if test \( "$PCAP_CONFIG" = "/usr/bin/pcap-config" \) -o \
                        \( "$PCAP_CONFIG" = "/usr/ccs/bin/pcap-config" \) ; then
                    #
                    # It's vendor-supplied.
                    #
                    case "$host_os" in

                    darwin*)
                        #
                        # This is macOS or another Darwin-based OS.
                        #
                        # That means that /usr/bin/pcap-config it
                        # may provide -I/usr/local/include with --cflags
                        # and -L/usr/local/lib with --libs, rather than
                        # pointing to the OS-supplied library and
                        # Xcode-supplied headers.  Remember that, so we
                        # ignore those values.
                        #
                        _broken_apple_pcap_config=yes

                        #
                        # Furthermore:
                        #
                        # macOS Sonoma's libpcap includes stub versions
                        # of the remote-capture APIs.  They are exported
                        # as "weakly linked symbols".
                        #
                        # Xcode 15 offers only a macOS Sonoma SDK, which
                        # has a .tbd file for libpcap that claims it
                        # includes those APIs.  (Newer versions of macOS
                        # don't provide the system shared libraries,
                        # they only provide the dyld shared cache
                        # containing those libraries, so the OS provides
                        # SDKs that include a .tbd file to use when
                        # linking.)
                        #
                        # This means that AC_CHECK_FUNCS() will think
                        # that the remote-capture APIs are present,
                        # including pcap_open() and
                        # pcap_findalldevs_ex().
                        #
                        # However, they are *not* present in macOS
                        # Ventura and earlier, which means that building
                        # on Ventura with Xcode 15 produces executables
                        # that fail to start because one of those APIs
                        # isn't found in the system libpcap.
                        #
                        # Protecting calls to those APIs with
                        # __builtin_available() does not appear to
                        # prevent this, for some unknown reason, and it
                        # doesn't even allow the program to compile with
                        # versions of Xcode prior to Xcode 15, as the
                        # pcap.h file doesn't specify minimum OS
                        # versions for those functions.
                        #
                        # Given all that, and given that the versions of
                        # the remote-capture APIs in Sonoma are stubs
                        # that always fail, there doesn't seem to be any
                        # point in checking for pcap_open() if we're
                        # linking against the Apple libpcap.
                        #
                        # However, if we're *not* linking against the
                        # Apple libpcap, we should check for it, so that
                        # we can use it if it's present.
                        #
                        # We know this is macOS and that we're using
                        # the system-provided pcap-config to find
                        # libpcap, so we know it'll be the system
                        # libpcap, and note that we should not search
                        # for remote-capture APIs.
                        #
                        _dont_check_for_remote_apis=yes
                        ;;

                    solaris*)
                        #
                        # This is Solaris 2 or later, i.e. SunOS 5.x.
                        #
                        # At least on Solaris 11; there's /usr/bin/pcap-config,
                        # which reports -L/usr/lib with --libs, causing
                        # the 32-bit libraries to be found, and there's
                        # /usr/bin/{64bitarch}/pcap-config, where {64bitarch}
                        # is a name for the 64-bit version of the instruction
                        # set, which reports -L /usr/lib/{64bitarch}, causing
                        # the 64-bit libraries to be found.
                        #
                        # So if we're building 64-bit targets, we replace
                        # PCAP_CONFIG with /usr/bin/{64bitarch}; we get
                        # {64bitarch} as the output of "isainfo -n".
                        #
                        # Are we building 32-bit or 64-bit?  Get the
                        # size of void *, and check that.
                        #
                        AC_CHECK_SIZEOF([void *])
                        if test ac_cv_sizeof_void_p -eq 8 ; then
                            isainfo_output=`isainfo -n`
                            if test ! -z "$isainfo_output" ; then
                                #
                                # Success - change PCAP_CONFIG.
                                #
                                PCAP_CONFIG=`echo $PCAP_CONFIG | sed "s;/bin/;/bin/$isainfo_output/;"`
                            fi
                        fi
                        ;;
                    esac
                fi
                #
                # Please read section 11.6 "Shell Substitutions"
                # in the autoconf manual before doing anything
                # to this that involves quoting.  Especially note
                # the statement "There is just no portable way to use
                # double-quoted strings inside double-quoted back-quoted
                # expressions (pfew!)."
                #
                cflags=`"$PCAP_CONFIG" --cflags`
                #
                # Work around macOS (and probably other Darwin) brokenness,
                # by not adding /usr/local/include if it's from the broken
                # Apple pcap-config.
                #
                if test "$_broken_apple_pcap_config" = "yes" ; then
                    #
                    # Strip -I/usr/local/include with sed.
                    #
                    cflags=`echo $cflags | sed 's;-I/usr/local/include;;'`
                fi
                $2="$cflags $$2"
                libpcap=`"$PCAP_CONFIG" --libs`
                #
                # Work around macOS (and probably other Darwin) brokenness,
                # by not adding /usr/local/lib if it's from the broken
                # Apple pcap-config.
                #
                if test "$_broken_apple_pcap_config" = "yes" ; then
                    #
                    # Strip -L/usr/local/lib with sed.
                    #
                    libpcap=`echo $libpcap | sed 's;-L/usr/local/lib;;'`
                fi
            else
                #
                # Not found; look for an installed pcap.
                #
                AC_CHECK_LIB(pcap, main, libpcap="-lpcap")
                if test $libpcap = FAIL ; then
                    AC_MSG_ERROR(see the INSTALL.md file for more info)
                fi
                dnl
                dnl Some versions of Red Hat Linux put "pcap.h" in
                dnl "/usr/include/pcap"; had the LBL folks done so,
                dnl that would have been a good idea, but for
                dnl the Red Hat folks to do so just breaks source
                dnl compatibility with other systems.
                dnl
                dnl We work around this by assuming that, as we didn't
                dnl find a local libpcap, libpcap is in /usr/lib or
                dnl /usr/local/lib and that the corresponding header
                dnl file is under one of those directories; if we don't
                dnl find it in either of those directories, we check to
                dnl see if it's in a "pcap" subdirectory of them and,
                dnl if so, add that subdirectory to the "-I" list.
                dnl
                dnl (We now also put pcap.h in /usr/include/pcap, but we
                dnl leave behind a /usr/include/pcap.h that includes it,
                dnl so you can still just include <pcap.h>.)
                dnl
                AC_MSG_CHECKING(for extraneous pcap header directories)
                if test \( ! -r /usr/local/include/pcap.h \) -a \
                        \( ! -r /usr/include/pcap.h \); then
                    if test -r /usr/local/include/pcap/pcap.h; then
                        d="/usr/local/include/pcap"
                    elif test -r /usr/include/pcap/pcap.h; then
                        d="/usr/include/pcap"
                    fi
                fi
                if test -z "$d" ; then
                    AC_MSG_RESULT(not found)
                else
                    $2="-I$d $$2"
                    AC_MSG_RESULT(found -- -I$d added)
                fi
            fi
        ])
    else
        #
        # We found a local libpcap.  Add it to the dependencies for
        # tcpdump.
        #
        $1=$libpcap

        #
        # Look for its pcap-config script.
        #
        AC_PATH_PROG(PCAP_CONFIG, pcap-config,, $local_pcap_dir)

        if test -n "$PCAP_CONFIG"; then
            #
            # We don't want its --cflags or --libs output, because
            # those presume it's installed.  For the C compiler flags,
            # we add the source directory for the local libpcap, so
            # we pick up its header files.
            #
            # We do, however, want its additional libraries, as required
            # when linking statically, because it makes calls to
            # routines in those libraries, so we'll need to link with
            # them, because we'll be linking statically with it.
            #
            # If it supports --static-pcap-only. use that, as we will be
            # linking with a static libpcap but won't be linking
            # statically with any of the libraries on which it depends;
            # those libraries might not even have static versions
            # installed.
            #
            # That means we need to find out the libraries on which
            # libpcap directly depends, so we can link with them, but we
            # don't need to link with the libraries on which those
            # libraries depend as, on all UN*Xes with which I'm
            # familiar, the libraries on which a shared library depends
            # are stored in the library and are automatically loaded by
            # the run-time linker, without the executable having to be
            # linked with those libraries.  (This allows a library to be
            # changed to depend on more libraries without breaking that
            # library's ABI.)
            #
            # The only way to test for that support is to see if the
            # script contains the string "static-pcap-only"; we can't
            # try using that flag and checking for errors, as the
            # versions of the script that didn't have that flag wouldn't
            # report or return an error for an unsupported command-line
            # flag.  Those older versions provided, with --static, only
            # the libraries on which libpcap depends, not the
            # dependencies of those libraries; the versions with
            # --static-pcap-only provide all the dependencies with
            # --static, for the benefit of programs that are completely
            # statically linked, and provide only the direct
            # dependencies with --static-pcap-only.
            #
            AC_MSG_CHECKING([whether $PCAP_CONFIG supports --static-pcap-only])
            if grep -s -q "static-pcap-only" "$PCAP_CONFIG"
            then
                AC_MSG_RESULT([yes])
                static_opt="--static-pcap-only"
            else
                AC_MSG_RESULT([no])
                static_opt="--static"
            fi
            $2="-I$local_pcap_dir $$2"
            additional_libs=`"$PCAP_CONFIG" $static_opt --additional-libs`
            libpcap="$libpcap $additional_libs"
        else
            #
            # It doesn't have a pcap-config script.
            # Make sure it has a pcap.h file.
            #
            places=`ls $srcdir/.. | sed -e 's,/$,,' -e "s,^,$srcdir/../," | \
                $EGREP '/libpcap-[[0-9]]*.[[0-9]]*(.[[0-9]]*)?([[ab]][[0-9]]*)?$'`
            places2=`ls .. | sed -e 's,/$,,' -e "s,^,../," | \
                $EGREP '/libpcap-[[0-9]]*.[[0-9]]*(.[[0-9]]*)?([[ab]][[0-9]]*)?$'`
            pcapH=FAIL
            if test -r $local_pcap_dir/pcap.h; then
                pcapH=$local_pcap_dir
            else
                for dir in $places $srcdir/../libpcap ../libpcap $srcdir/libpcap $places2 ; do
                    if test -r $dir/pcap.h ; then
                        pcapH=$dir
                    fi
                done
            fi

            if test $pcapH = FAIL ; then
                AC_MSG_ERROR(cannot find pcap.h: see the INSTALL.md file)
            fi

            #
            # Force the compiler to look for header files in the
            # directory containing pcap.h.
            #
            $2="-I$pcapH $$2"
        fi
    fi

    if test -z "$PKG_CONFIG" -a -z "$PCAP_CONFIG"; then
        #
        # We don't have pkg-config or pcap-config; find out any additional
        # link flags we need.  (If we have pkg-config or pcap-config, we
        # assume it tells us what we need.)
        #
        case "$host_os" in

        aix*)
            #
            # If libpcap is DLPI-based, we have to use /lib/pse.exp if
            # present, as we use the STREAMS routines.
            #
            # (XXX - true only if we're linking with a static libpcap?)
            #
            pseexe="/lib/pse.exp"
            AC_MSG_CHECKING(for $pseexe)
            if test -f $pseexe ; then
                AC_MSG_RESULT(yes)
                LIBS="$LIBS -I:$pseexe"
            fi

            #
            # If libpcap is BPF-based, we need "-lodm" and "-lcfg", as
            # we use them to load the BPF module.
            #
            # (XXX - true only if we're linking with a static libpcap?)
            #
            LIBS="$LIBS -lodm -lcfg"
            ;;

	solaris*)
            # libdlpi is needed for Solaris 11 and later.
            AC_CHECK_LIB(dlpi, dlpi_walk, LIBS="$LIBS -ldlpi" LDFLAGS="-L/lib $LDFLAGS", ,-L/lib)
            ;;
        esac
    fi

    LIBS="$libpcap $LIBS"

    dnl
    dnl Check for "pcap_loop()", to make sure we found a working
    dnl libpcap and have all the right other libraries with which
    dnl to link.  (Otherwise, the checks below will fail, not
    dnl because the routines are missing from the library, but
    dnl because we aren't linking properly with libpcap, and
    dnl that will cause confusing errors at build time.)
    dnl
    AC_CHECK_FUNC(pcap_loop,,
    [
        AC_MSG_ERROR(
[
1. Do you try to build a 32-bit tcpdump with a 64-bit libpcap or vice versa?
2. This is a bug, please follow the guidelines in CONTRIBUTING.md and include
the config.log file in your report.  If you have downloaded libpcap from
tcpdump.org, and built it yourself, please also include the config.log
file from the libpcap source directory, the Makefile from the libpcap
source directory, and the output of the make process for libpcap, as
this could be a problem with the libpcap that was built, and we will
not be able to determine why this is happening, and thus will not be
able to fix it, without that information, as we have not been able to
reproduce this problem ourselves.])
    ])
])

dnl
dnl If the file .devel exists:
dnl	Add some warning flags if the compiler supports them
dnl	If an os prototype include exists, symlink os-proto.h to it
dnl
dnl usage:
dnl
dnl	AC_LBL_DEVEL(copt)
dnl
dnl results:
dnl
dnl	$1 (copt appended)
dnl	HAVE_OS_PROTO_H (defined)
dnl	os-proto.h (symlinked)
dnl
AC_DEFUN(AC_LBL_DEVEL,
    [rm -f os-proto.h
    if test "${LBL_CFLAGS+set}" = set; then
	    $1="$$1 ${LBL_CFLAGS}"
    fi
    if test -f .devel ; then
	    #
	    # Skip all the warning option stuff on some compilers.
	    #
	    if test "$ac_lbl_cc_dont_try_gcc_dashW" != yes; then
		    AC_LBL_CHECK_COMPILER_OPT($1, -W)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wall)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wassign-enum)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wcast-qual)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wmissing-prototypes)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wmissing-variable-declarations)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wnull-pointer-subtraction)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wold-style-definition)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wpedantic)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wpointer-arith)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wpointer-sign)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wshadow)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wsign-compare)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wstrict-prototypes)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wundef)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wunreachable-code-return)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wunused-but-set-parameter)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wunused-but-set-variable)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wused-but-marked-unused)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wwrite-strings)
	    fi
	    AC_LBL_CHECK_DEPENDENCY_GENERATION_OPT()
	    AC_MSG_CHECKING([whether to use an os-proto.h header])
	    os=`echo $host_os | sed -e 's/\([[0-9]][[0-9]]*\)[[^0-9]].*$/\1/'`
	    name="lbl/os-$os.h"
	    if test -f $name ; then
		    AC_MSG_RESULT([yes, at "$name"])
		    ln -s $name os-proto.h
		    AC_DEFINE(HAVE_OS_PROTO_H, 1,
			[if there's an os-proto.h for this platform, to use additional prototypes])
	    else
		    AC_MSG_RESULT([no])
	    fi
    fi])

dnl
dnl This is a simplified adaptation of AC_LBL_LIBRARY_NET from libpcap.
dnl In this context tcpdump needs gethostbyaddr() only.
dnl
AC_DEFUN(AC_LBL_LIBRARY_NET, [
    AC_CHECK_FUNC(gethostbyaddr,,
    [
	AC_CHECK_LIB(socket, gethostbyaddr,
	[
	    LIBS="-lsocket -lnsl $LIBS"
	],
	[
	    AC_CHECK_LIB(network, gethostbyaddr,
	    [
		LIBS="-lnetwork $LIBS"
	    ],
	    [
		AC_MSG_ERROR([gethostbyaddr is required, but wasn't found])
	    ])
	], -lnsl)
    ])
])

m4_ifndef([AC_CONFIG_MACRO_DIRS], [m4_defun([_AM_CONFIG_MACRO_DIRS], [])m4_defun([AC_CONFIG_MACRO_DIRS], [_AM_CONFIG_MACRO_DIRS($@)])])
dnl pkg.m4 - Macros to locate and utilise pkg-config.   -*- Autoconf -*-
dnl serial 11 (pkg-config-0.29)
dnl
dnl Copyright © 2004 Scott James Remnant <scott@netsplit.com>.
dnl Copyright © 2012-2015 Dan Nicholson <dbn.lists@gmail.com>
dnl
dnl This program is free software; you can redistribute it and/or modify
dnl it under the terms of the GNU General Public License as published by
dnl the Free Software Foundation; either version 2 of the License, or
dnl (at your option) any later version.
dnl
dnl This program is distributed in the hope that it will be useful, but
dnl WITHOUT ANY WARRANTY; without even the implied warranty of
dnl MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
dnl General Public License for more details.
dnl
dnl You should have received a copy of the GNU General Public License
dnl along with this program; if not, write to the Free Software
dnl Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
dnl 02111-1307, USA.
dnl
dnl As a special exception to the GNU General Public License, if you
dnl distribute this file as part of a program that contains a
dnl configuration script generated by Autoconf, you may include it under
dnl the same distribution terms that you use for the rest of that
dnl program.

dnl PKG_PREREQ(MIN-VERSION)
dnl -----------------------
dnl Since: 0.29
dnl
dnl Verify that the version of the pkg-config macros are at least
dnl MIN-VERSION. Unlike PKG_PROG_PKG_CONFIG, which checks the user's
dnl installed version of pkg-config, this checks the developer's version
dnl of pkg.m4 when generating configure.
dnl
dnl To ensure that this macro is defined, also add:
dnl m4_ifndef([PKG_PREREQ],
dnl     [m4_fatal([must install pkg-config 0.29 or later before running autoconf/autogen])])
dnl
dnl See the "Since" comment for each macro you use to see what version
dnl of the macros you require.
m4_defun([PKG_PREREQ],
[m4_define([PKG_MACROS_VERSION], [0.29])
m4_if(m4_version_compare(PKG_MACROS_VERSION, [$1]), -1,
    [m4_fatal([pkg.m4 version $1 or higher is required but ]PKG_MACROS_VERSION[ found])])
])dnl PKG_PREREQ

dnl PKG_PROG_PKG_CONFIG([MIN-VERSION])
dnl ----------------------------------
dnl Since: 0.16
dnl
dnl Search for the pkg-config tool and set the PKG_CONFIG variable to
dnl first found in the path. Checks that the version of pkg-config found
dnl is at least MIN-VERSION. If MIN-VERSION is not specified, 0.17.0 is
dnl used since that's the first version where --static was supported.
AC_DEFUN([PKG_PROG_PKG_CONFIG],
[m4_pattern_forbid([^_?PKG_[A-Z_]+$])
m4_pattern_allow([^PKG_CONFIG(_(PATH|LIBDIR|SYSROOT_DIR|ALLOW_SYSTEM_(CFLAGS|LIBS)))?$])
m4_pattern_allow([^PKG_CONFIG_(DISABLE_UNINSTALLED|TOP_BUILD_DIR|DEBUG_SPEW)$])
AC_ARG_VAR([PKG_CONFIG], [path to pkg-config utility])
AC_ARG_VAR([PKG_CONFIG_PATH], [directories to add to pkg-config's search path])
AC_ARG_VAR([PKG_CONFIG_LIBDIR], [path overriding pkg-config's built-in search path])

if test "x$ac_cv_env_PKG_CONFIG_set" != "xset"; then
	AC_PATH_TOOL([PKG_CONFIG], [pkg-config])
fi
if test -n "$PKG_CONFIG"; then
	_pkg_min_version=m4_default([$1], [0.17.0])
	AC_MSG_CHECKING([pkg-config is at least version $_pkg_min_version])
	if $PKG_CONFIG --atleast-pkgconfig-version $_pkg_min_version; then
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
		PKG_CONFIG=""
	fi
fi[]dnl
])dnl PKG_PROG_PKG_CONFIG

dnl PKG_CHECK_EXISTS(MODULE, [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
dnl -------------------------------------------------------------------
dnl Check to see whether a particular module exists. Similar to
dnl PKG_CHECK_MODULE(), but does not set variables or print errors.
dnl
dnl --exists was introduced in pkg-config 0.4.0; that dates back to late
dnl 2000, and we require 0.17.0 or later anyway, so we won't worry about
dnl earlier releases that lack it.
dnl
AC_DEFUN([PKG_CHECK_EXISTS],
[
if test -n "$PKG_CONFIG" && \
    AC_RUN_LOG([$PKG_CONFIG --exists --print-errors "$1"]); then
  m4_default([$2], [:])
m4_ifvaln([$3], [else
  $3])dnl
fi])

dnl _PKG_CONFIG_WITH_FLAGS([VARIABLE], [FLAGS], [MODULE])
dnl ---------------------------------------------
dnl Internal wrapper calling pkg-config via PKG_CONFIG and, if
dnl pkg-config fails, reporting the error and quitting.
m4_define([_PKG_CONFIG_WITH_FLAGS],
[if test ! -n "$$1"; then
    $1=`$PKG_CONFIG $2 "$3" 2>/dev/null`
    if test "x$?" != "x0"; then
        #
        # That failed - report an error.
        # Re-run the command, telling pkg-config to print an error
        # message, capture the error message, and report it.
        # This causes the configuration script to fail, as it means
        # the script is almost certainly doing something wrong.
        #
        _PKG_SHORT_ERRORS_SUPPORTED
	if test $_pkg_short_errors_supported = yes; then
	    _pkg_error_string=`$PKG_CONFIG --short-errors --print-errors $2 "$3" 2>&1`
	else
	    _pkg_error_string=`$PKG_CONFIG --print-errors $2 "$3" 2>&1`
	fi
        AC_MSG_ERROR([$PKG_CONFIG $2 "$3" failed: $_pkg_error_string])
    fi
 fi[]dnl
])dnl _PKG_CONFIG_WITH_FLAGS


dnl _PKG_CONFIG([VARIABLE], [FLAGS], [MODULE])
dnl ---------------------------------------------
dnl Internal wrapper calling pkg-config via PKG_CONFIG and setting
dnl pkg_failed based on the result.
m4_define([_PKG_CONFIG],
[if test -n "$$1"; then
    pkg_cv_[]$1="$$1"
 elif test -n "$PKG_CONFIG"; then
    PKG_CHECK_EXISTS([$3],
                     [pkg_cv_[]$1=`$PKG_CONFIG $2 "$3" 2>/dev/null`
		      test "x$?" != "x0" && pkg_failed=yes ],
		     [pkg_failed=yes])
 else
    pkg_failed=untried
fi[]dnl
])dnl _PKG_CONFIG

dnl _PKG_SHORT_ERRORS_SUPPORTED
dnl ---------------------------
dnl Internal check to see if pkg-config supports short errors.
AC_DEFUN([_PKG_SHORT_ERRORS_SUPPORTED],
[
if $PKG_CONFIG --atleast-pkgconfig-version 0.20; then
        _pkg_short_errors_supported=yes
else
        _pkg_short_errors_supported=no
fi[]dnl
])dnl _PKG_SHORT_ERRORS_SUPPORTED


dnl PKG_CHECK_MODULE(VARIABLE-PREFIX, MODULE, [ACTION-IF-FOUND],
dnl   [ACTION-IF-NOT-FOUND])
dnl --------------------------------------------------------------
dnl Check to see whether a particular module exists and, if it
dnl does, set <MODULE>_CFLAGS, <MODULE>_LIBS, and <MODULE>_LIBS_STATIC
dnl to the results of --cflags, --libs, and --libs --static,
dnl respectively.
dnl
AC_DEFUN([PKG_CHECK_MODULE],
[
if test -n "$PKG_CONFIG"; then
    AC_ARG_VAR([$1][_CFLAGS], [C compiler flags for $2, overriding pkg-config])dnl
    AC_ARG_VAR([$1][_LIBS], [linker flags for $2, overriding pkg-config])dnl
    AC_ARG_VAR([$1][_LIBS_STATIC], [static-link linker flags for $2, overriding pkg-config])dnl

    AC_MSG_CHECKING([for $2 with pkg-config])
    if AC_RUN_LOG([$PKG_CONFIG --exists --print-errors "$2"]); then
	#
	# The package was found, so try to get its C flags and
	# libraries.
	#
        AC_MSG_RESULT([found])
	_PKG_CONFIG_WITH_FLAGS([$1][_CFLAGS], [--cflags], [$2])
	_PKG_CONFIG_WITH_FLAGS([$1][_LIBS], [--libs], [$2])
	_PKG_CONFIG_WITH_FLAGS([$1][_LIBS_STATIC], [--libs --static], [$2])
        m4_default([$3], [:])
    else
        AC_MSG_RESULT([not found])
        m4_default([$4], [:])
    fi
else
    # No pkg-config, so obviously not found with pkg-config.
    m4_default([$4], [:])
fi
])dnl PKG_CHECK_MODULE


dnl PKG_CHECK_MODULE_STATIC(VARIABLE-PREFIX, MODULE, [ACTION-IF-FOUND],
dnl   [ACTION-IF-NOT-FOUND])
dnl ---------------------------------------------------------------------
dnl Since: 0.29
dnl
dnl Checks for existence of MODULE and gathers its build flags with
dnl static libraries enabled. Sets VARIABLE-PREFIX_CFLAGS from --cflags
dnl and VARIABLE-PREFIX_LIBS from --libs.
AC_DEFUN([PKG_CHECK_MODULE_STATIC],
[
_save_PKG_CONFIG=$PKG_CONFIG
PKG_CONFIG="$PKG_CONFIG --static"
PKG_CHECK_MODULE($@)
PKG_CONFIG=$_save_PKG_CONFIG[]dnl
])dnl PKG_CHECK_MODULE_STATIC


dnl PKG_INSTALLDIR([DIRECTORY])
dnl -------------------------
dnl Since: 0.27
dnl
dnl Substitutes the variable pkgconfigdir as the location where a module
dnl should install pkg-config .pc files. By default the directory is
dnl $libdir/pkgconfig, but the default can be changed by passing
dnl DIRECTORY. The user can override through the --with-pkgconfigdir
dnl parameter.
AC_DEFUN([PKG_INSTALLDIR],
[m4_pushdef([pkg_default], [m4_default([$1], ['${libdir}/pkgconfig'])])
m4_pushdef([pkg_description],
    [pkg-config installation directory @<:@]pkg_default[@:>@])
AC_ARG_WITH([pkgconfigdir],
    [AS_HELP_STRING([--with-pkgconfigdir], pkg_description)],,
    [with_pkgconfigdir=]pkg_default)
AC_SUBST([pkgconfigdir], [$with_pkgconfigdir])
m4_popdef([pkg_default])
m4_popdef([pkg_description])
])dnl PKG_INSTALLDIR


dnl PKG_NOARCH_INSTALLDIR([DIRECTORY])
dnl --------------------------------
dnl Since: 0.27
dnl
dnl Substitutes the variable noarch_pkgconfigdir as the location where a
dnl module should install arch-independent pkg-config .pc files. By
dnl default the directory is $datadir/pkgconfig, but the default can be
dnl changed by passing DIRECTORY. The user can override through the
dnl --with-noarch-pkgconfigdir parameter.
AC_DEFUN([PKG_NOARCH_INSTALLDIR],
[m4_pushdef([pkg_default], [m4_default([$1], ['${datadir}/pkgconfig'])])
m4_pushdef([pkg_description],
    [pkg-config arch-independent installation directory @<:@]pkg_default[@:>@])
AC_ARG_WITH([noarch-pkgconfigdir],
    [AS_HELP_STRING([--with-noarch-pkgconfigdir], pkg_description)],,
    [with_noarch_pkgconfigdir=]pkg_default)
AC_SUBST([noarch_pkgconfigdir], [$with_noarch_pkgconfigdir])
m4_popdef([pkg_default])
m4_popdef([pkg_description])
])dnl PKG_NOARCH_INSTALLDIR


dnl PKG_CHECK_VAR(VARIABLE, MODULE, CONFIG-VARIABLE,
dnl [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
dnl -------------------------------------------
dnl Since: 0.28
dnl
dnl Retrieves the value of the pkg-config variable for the given module.
AC_DEFUN([PKG_CHECK_VAR],
[
AC_ARG_VAR([$1], [value of $3 for $2, overriding pkg-config])dnl

_PKG_CONFIG([$1], [--variable="][$3]["], [$2])
AS_VAR_COPY([$1], [pkg_cv_][$1])

AS_VAR_IF([$1], [""], [$5], [$4])dnl
])dnl PKG_CHECK_VAR
