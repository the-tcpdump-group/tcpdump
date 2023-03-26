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

	    irix*)
		    #
		    # MIPS C, which is what we presume we're using, doesn't
		    # necessarily exit with a non-zero exit status if we
		    # hand it an invalid -W flag, can't be forced to do
		    # so, and doesn't handle GCC-style -W flags, so we
		    # don't want to try using GCC-style -W flags.
		    #
		    ac_lbl_cc_dont_try_gcc_dashW=yes
		    #
		    # It also, apparently, defaults to "char" being
		    # unsigned, unlike most other C implementations;
		    # I suppose we could say "signed char" whenever
		    # we want to guarantee a signed "char", but let's
		    # just force signed chars.
		    #
		    # -xansi is normally the default, but the
		    # configure script was setting it; perhaps -cckr
		    # was the default in the Old Days.  (Then again,
		    # that would probably be for backwards compatibility
		    # in the days when ANSI C was Shiny and New, i.e.
		    # 1989 and the early '90's, so maybe we can just
		    # drop support for those compilers.)
		    #
		    # -g is equivalent to -g2, which turns off
		    # optimization; we choose -g3, which generates
		    # debugging information but doesn't turn off
		    # optimization (even if the optimization would
		    # cause inaccuracies in debugging).
		    #
		    $1="$$1 -xansi -signed -g3"
		    ;;

	    osf*)
		    #
		    # Presumed to be DEC OSF/1, Digital UNIX, or
		    # Tru64 UNIX.
		    #
		    # The DEC C compiler, which is what we presume we're
		    # using, doesn't exit with a non-zero exit status if we
		    # hand it an invalid -W flag, can't be forced to do
		    # so, and doesn't handle GCC-style -W flags, so we
		    # don't want to try using GCC-style -W flags.
		    #
		    ac_lbl_cc_dont_try_gcc_dashW=yes
		    #
		    # -g is equivalent to -g2, which turns off
		    # optimization; we choose -g3, which generates
		    # debugging information but doesn't turn off
		    # optimization (even if the optimization would
		    # cause inaccuracies in debugging).
		    #
		    $1="$$1 -g3"
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

		irix*|osf*|darwin*)
			#
			# MIPS C for IRIX, DEC C, and clang all use -M.
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
        # Look for an installed pkg-config.
        #
        AC_PATH_TOOL(PKG_CONFIG, pkg-config)
        if test -n "$PKG_CONFIG" ; then
            #
            # We have it.  Are there .pc files for libpcap?
            #
            # --exists was introduced in pkg-config 0.4.0; that
            # dates back to late 2000, so we won't worry about
            # earlier releases that lack it.
            #
            AC_MSG_CHECKING(whether there are .pc files for libpcap)
            if "$PKG_CONFIG" libpcap --exists ; then
                #
                # Yes, so we can use pkg-config to get configuration
                # information for libpcap.
                #
                AC_MSG_RESULT(yes)
                pkg_config_usable=yes
            else
                #
                # No, so we can't use pkg-config to get configuration
                # information for libpcap.
                #
                AC_MSG_RESULT(no)
                pkg_config_usable=no
            fi
        else
            #
            # We don't have it, so we obviously can't use it.
            #
            pkg_config_usable=no
        fi
        if test "$pkg_config_usable" = "yes" ; then
            #
            # Found both - use pkg-config to get the include flags for
            # libpcap and the flags to link with libpcap.
            #
            # Please read section 11.6 "Shell Substitutions"
            # in the autoconf manual before doing anything
            # to this that involves quoting.  Especially note
            # the statement "There is just no portable way to use
            # double-quoted strings inside double-quoted back-quoted
            # expressions (pfew!)."
            #
            cflags=`"$PKG_CONFIG" libpcap --cflags`
            $2="$cflags $$2"
            libpcap=`"$PKG_CONFIG" libpcap --libs`
        else
            #
            # No pkg-config
            # Look for an installed pcap-config.
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
        fi
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
            if grep "static-pcap-only" "$PCAP_CONFIG" >/dev/null 2>&1
            then
                static_opt="--static-pcap-only"
            else
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
[This is a bug, please follow the guidelines in CONTRIBUTING.md and include the
config.log file in your report.  If you have downloaded libpcap from
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
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wold-style-definition)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wpedantic)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wpointer-arith)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wpointer-sign)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wshadow)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wsign-compare)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wstrict-prototypes)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wunreachable-code-return)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wused-but-marked-unused)
		    AC_LBL_CHECK_COMPILER_OPT($1, -Wwrite-strings)
	    fi
	    AC_LBL_CHECK_DEPENDENCY_GENERATION_OPT()
	    #
	    # We used to set -n32 for IRIX 6 when not using GCC (presumed
	    # to mean that we're using MIPS C or MIPSpro C); it specified
	    # the "new" faster 32-bit ABI, introduced in IRIX 6.2.  I'm
	    # not sure why that would be something to do *only* with a
	    # .devel file; why should the ABI for which we produce code
	    # depend on .devel?
	    #
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
dnl AC_LBL_LIBRARY_NET
dnl
dnl This test is for network applications that need socket() and
dnl gethostbyaddr() -ish functions.  Under Solaris, those applications
dnl need to link with "-lsocket -lnsl".  Under IRIX, they need to link
dnl with "-lnsl" but should *not* link with "-lsocket" because
dnl libsocket.a breaks a number of things (for instance:
dnl gethostbyaddr() under IRIX 5.2, and snoop sockets under most
dnl versions of IRIX).
dnl
dnl Unfortunately, many application developers are not aware of this,
dnl and mistakenly write tests that cause -lsocket to be used under
dnl IRIX.  It is also easy to write tests that cause -lnsl to be used
dnl under operating systems where neither are necessary (or useful),
dnl such as SunOS 4.1.4, which uses -lnsl for TLI.
dnl
dnl This test exists so that every application developer does not test
dnl this in a different, and subtly broken fashion.

dnl It has been argued that this test should be broken up into two
dnl separate tests, one for the resolver libraries, and one for the
dnl libraries necessary for using Sockets API. Unfortunately, the two
dnl are carefully intertwined and allowing the autoconf user to use
dnl them independently potentially results in unfortunate ordering
dnl dependencies -- as such, such component macros would have to
dnl carefully use indirection and be aware if the other components were
dnl executed. Since other autoconf macros do not go to this trouble,
dnl and almost no applications use sockets without the resolver, this
dnl complexity has not been implemented.
dnl
dnl The check for libresolv is in case you are attempting to link
dnl statically and happen to have a libresolv.a lying around (and no
dnl libnsl.a).
dnl
AC_DEFUN(AC_LBL_LIBRARY_NET, [
    # Most operating systems have gethostbyaddr() in the default searched
    # libraries (i.e. libc):
    # Some OSes (eg. Solaris) place it in libnsl
    # Some strange OSes (SINIX) have it in libsocket:
    AC_SEARCH_LIBS(gethostbyaddr, network nsl socket resolv)
    # Unfortunately libsocket sometimes depends on libnsl and
    # AC_SEARCH_LIBS isn't up to the task of handling dependencies like this.
    if test "$ac_cv_search_gethostbyaddr" = "no"
    then
	AC_CHECK_LIB(socket, gethostbyaddr,
                     LIBS="-lsocket -lnsl $LIBS", , -lnsl)
    fi
    AC_SEARCH_LIBS(socket, socket, ,
	AC_CHECK_LIB(socket, socket, LIBS="-lsocket -lnsl $LIBS", , -lnsl))
    # DLPI needs putmsg under HPUX so test for -lstr while we're at it
    AC_SEARCH_LIBS(putmsg, str)
    ])
