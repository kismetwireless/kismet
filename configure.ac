# Process this file with autoconf to produce a configure script.
AC_INIT

VERSION=`cat VERSION`
AC_SUBST(VERSION)

BUNDLE_MSGPACK=./msgpack-1.4.1

#m4_include([m4/acx_pthread.m4])
#m4_include([m4/ax_cxx_compile_stdcxx.m4])
#m4_include([m4/ax_cxx_compile_stdcxx_11.m4])
AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_SRCDIR([kismet.h])

AC_CONFIG_SUBDIRS([${BUNDLE_MSGPACK}])

AC_PREREQ(2.57)

# Check for host type
AC_CANONICAL_HOST

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_CPP

AC_LANG_CPLUSPLUS

# Liberated from ethereal's configure.in
#
# Add any platform-specific compiler flags needed.
#
AC_MSG_CHECKING(for platform-specific compiler flags)
if test "x$GCC" = x
then
    #
    # Not GCC - assume it's the vendor's compiler.
    #
    case "$host_os" in
	darwin10*)
		# Snow leopard and newer, no -bundle in plugins
        CFLAGS="-no-cpp-precomp $CFLAGS"
		LDFLAGS="$LDFLAGS -framework Foundation -framework CoreFoundation -F/System/Library/PrivateFrameworks -framework Apple80211 -framework IOKit"
		PLUGINLDFLAGS="-flat_namespace -undefined suppress"
        AC_MSG_RESULT(Apple OSX Snow Leopard or newer)
		AC_DEFINE(SYS_DARWIN, 1, Compiling for OSX/Darwin)
		darwin="yes"
        ;;
    darwin*)
        #
        # It may be called "cc", but it's really a GCC derivative
        # with a problematic special precompiler and precompiled
        # headers; turn off the special precompiler, as some
        # apparently-legal code won't compile with its precompiled
        # headers.
        #
        CFLAGS="-no-cpp-precomp $CFLAGS"
		LDFLAGS="$LDFLAGS -framework Foundation -framework CoreFoundation -F/System/Library/PrivateFrameworks -framework Apple80211 -framework IOKit"
		PLUGINLDFLAGS="-bundle -flat_namespace -undefined suppress"
        AC_MSG_RESULT(Apple GCC - added Apple80211 frameworks and no-precomp)
		AC_DEFINE(SYS_DARWIN, 1, Compiling for OSX/Darwin)
		darwin="yes"
        ;;
	linux*)
		AC_MSG_RESULT(none needed)
		AC_DEFINE(SYS_LINUX, 1, Compiling for Linux OS)
        linux="yes"
		;;
	freebsd*)
		AC_MSG_RESULT(none needed)
		AC_DEFINE(SYS_FREEBSD, 1, Compiling for FreeBSD)
		bsd="yes"
		;;
	openbsd*)
		AC_MSG_RESULT(none needed)
		AC_DEFINE(SYS_OPENBSD, 1, Compiling for OpenBSD)
		bsd="yes"
		;;
	netbsd*)
		AC_MSG_RESULT(adding pkgsrc locations)
		CPPFLAGS="$CPPFLAGS -I/usr/pkg/include"
		LDFLAGS="$LDFLAGS -L/usr/pkg/lib"
		AC_DEFINE(SYS_NETBSD, 1, Compiling for NetBSD)
		bsd="yes"
		;;
	cygwin*)
		AC_MSG_RESULT(none needed)
		AC_DEFINE(SYS_CYGWIN, 1, Compiling for Cygwin)
		cygwin="yes"
		;;
    *)
        AC_MSG_RESULT(none needed)
        ;;
    esac
else
    case "$host_os" in
	darwin10*)
		# Snow leopard and newer, no -bundle in plugins
        CFLAGS="-no-cpp-precomp $CFLAGS"
		LDFLAGS="$LDFLAGS -framework Foundation -framework CoreFoundation -F/System/Library/PrivateFrameworks -framework Apple80211 -framework IOKit"
		PLUGINLDFLAGS="-flat_namespace -undefined suppress"
        AC_MSG_RESULT(Apple OSX Snow Leopard or newer)
		AC_DEFINE(SYS_DARWIN, 1, Compiling for OSX/Darwin)
		darwin="yes"
        ;;
    darwin*)
        #
        # See comments above about Apple's lovely C compiler.
        #
        CFLAGS="-no-cpp-precomp $CFLAGS"
		LDFLAGS="$LDFLAGS -framework Foundation -framework CoreFoundation -F/System/Library/PrivateFrameworks -framework Apple80211 -framework IOKit"
		PLUGINLDFLAGS="-bundle -flat_namespace -undefined suppress"
        AC_MSG_RESULT(Apple GCC - added Apple80211 frameworks and no-precomp)
		AC_DEFINE(SYS_DARWIN, 1, Compiling for OSX/Darwin)
		darwin="yes"
        ;;
	linux*)
		AC_MSG_RESULT(none needed)
		AC_DEFINE(SYS_LINUX, 1, Compiling for Linux OS)
        linux="yes"
		;;
    freebsd*)
        AC_MSG_RESULT(none needed)
        AC_DEFINE(SYS_FREEBSD, 1, Compiling for FreeBSD)
		bsd="yes"
        ;;
    openbsd*)
        AC_MSG_RESULT(none needed)
        AC_DEFINE(SYS_OPENBSD, 1, Compiling for OpenBSD)
		bsd="yes"
        ;;
    netbsd*)
		AC_MSG_RESULT(adding pkgsrc locations)
		CPPFLAGS="$CPPFLAGS -I/usr/pkg/include"
		LDFLAGS="$LDFLAGS -L/usr/pkg/lib"
        AC_DEFINE(SYS_NETBSD, 1, Compiling for NetBSD)
		bsd="yes"
        ;;
	cygwin*)
		AC_MSG_RESULT(none needed)
		AC_DEFINE(SYS_CYGWIN, 1, Compiling for Cygwin)
		cygwin="yes"
		;;
    *)
        AC_MSG_RESULT(none needed)
        ;;
    esac
fi

AX_CXX_COMPILE_STDCXX_11(, [mandatory])

AC_SUBST(PLUGINLDFLAGS)

if test "$cygwin" = "yes"; then
	AC_MSG_CHECKING(cygwin compile flags)
	AC_MSG_RESULT(__MINGW32__)
	CXXFLAGS="$CXXFLAGS -D__MINGW32__"
else
	# cygwin doesn't like rdynamic, will this hurt us?
	LDFLAGS="$LDFLAGS -rdynamic"
fi

AC_CONFIG_SRCDIR([kismet_server.cc])
AC_CONFIG_HEADER([config.h])

# Config location for code to default to
CONFFILE_DIR=$sysconfdir
CONFFILE_DIR=`(
    test "$prefix" = NONE && prefix=$ac_default_prefix
    test "$exec_prefix" = NONE && exec_prefix=${prefix}
    eval echo "$CONFFILE_DIR"
)`
AC_DEFINE_UNQUOTED(SYSCONF_LOC, "$CONFFILE_DIR", system config directory)

LOCALSTATE_DIR=$localstatedir
LOCALSTATE_DIR=`(
                 test "$prefix" = NONE && prefix=$ac_default_prefix
                 test "$exec_prefix" = NONE && exec_prefix=${prefix}
                 eval echo "$LOCALSTATE_DIR"
                )`
AC_DEFINE_UNQUOTED(LOCALSTATE_DIR, "$LOCALSTATE_DIR", system state directory)

BIN_DIR=$bindir
BIN_DIR=`(
    test "$prefix" = NONE && prefix=$ac_default_prefix
    test "$exec_prefix" = NONE && exec_prefix=${prefix}
    eval echo "$BIN_DIR"
)`
AC_DEFINE_UNQUOTED(BIN_LOC, "$BIN_DIR", system binary directory)

LIB_DIR=$libdir
LIB_DIR=`(
    test "$prefix" = NONE && prefix=$ac_default_prefix
    test "$exec_prefix" = NONE && exec_prefix=${prefix}
    eval echo "$LIB_DIR"
)`
AC_DEFINE_UNQUOTED(LIB_LOC, "$LIB_DIR", system library directory)

DATA_DIR=$datarootdir
DATA_DIR=`(
    test "$prefix" = NONE && prefix=$ac_default_prefix
    test "$exec_prefix" = NONE && exec_prefix=${prefix}
    eval echo "$DATA_DIR"
)`
AC_DEFINE_UNQUOTED(DATA_LOC, "$DATA_DIR", system data directory)

# Check for endian
AC_C_BIGENDIAN

# Checks for header files.
AC_CHECK_HEADERS([errno.h stdlib.h string.h sys/socket.h sys/time.h sys/wait.h unistd.h sys/types.h netdb.h],
	AC_DEFINE(HAVE_SYSHEADERS, 1, System headers are there),
	AC_MSG_ERROR(Missing required system header))

AC_CHECK_HEADERS([getopt.h])
AC_CHECK_HEADERS([glob.h])

# Configure for a remote-capture-only build
caponly=0
AC_ARG_ENABLE(capture-tools-only,
	[  --enable-capture-tools-only  Configure and build for capture tools and remote only],
	[case "${enableval}" in
	  no) caponly=0 ;;
	   *) caponly=1 ;;
	 esac],
	[caponly=0]
)

HAVE_LIBHACKRF=0
HAVE_LIBFFTW3=0
HAVE_HACKRF_H=0
HAVE_FFTW3_H=0
BUILD_HACKRF_SWEEP=0
HACKRF_MISSING_REASON="Missing required libhack/libfftw3 libraries"

AC_CHECK_HEADERS([libhackrf/hackrf.h],
    HAVE_HACKRF_H=1,
    AC_MSG_WARN("Missing hackrf.h from libhackrf"))
AC_CHECK_HEADERS([fftw3.h],
    HAVE_FFTW3_H=1,
    AC_MSG_WARN("Missing fftw3.h from libfftw"))

if test "$HAVE_HACKRF_H" -eq 1; then
    AC_CHECK_LIB([hackrf], [hackrf_init],
			HAVE_LIBHACKRF=1,
			 AC_MSG_WARN([libhackrf not available]))
else
    HACKRF_MISSING_REASON="Missing libhackrf/hackrf.h"
fi

if test "$HAVE_FFTW3_H" -eq 1; then
    AC_CHECK_LIB([fftw3], [fftw_malloc],
            HAVE_LIBFFTW3=1,
            AC_MSG_WARN([libfftw3 not available]))
else
    HACKRF_MISSING_REASON="missing libfftw3.h"
fi

if test "$HAVE_LIBHACKRF" -eq 1 && test "$HAVE_LIBFFTW3" -eq 1; then
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
    		#include <libhackrf/hackrf.h>
    		]], [[
            int s = SAMPLES_PER_BLOCK;
    		return 0;
    		]])],[hackrfsweep=1],[hackrfsweep=0])
    if test "$hackrfsweep" -eq 1; then
        AC_DEFINE(BUILD_HACKRF_SWEEP, 1, Able to build hackrf sweep source)
        BUILD_HACKRF_SWEEP=1
        DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_HACKRF_SWEEP)"
    else
        AC_MSG_WARN([Old version of libhack does not contain sweep code])
        HACKRF_MISSING_REASON="old version of libhackrf found"
    fi
else
    HACKRF_MISSING_REASON="missing libhackrf or libfftw3"
fi

HAVE_LIBDW=0
HAVE_LIBBFD=0

AC_CHECK_LIB([dw], [dwarf_begin], HAVE_LIBDW=1)
AC_CHECK_LIB([bfd], [bfd_alloc], HAVE_LIBBFD=1)

if test "$HAVE_LIBDW" -eq 1; then
    AC_CHECK_HEADERS([elfutils/libdw.h elfutils/libdwfl.h dwarf.h], DEF_BW_HAS_LIBDW=1)
fi

if test "$HAVE_LIBBFD" -eq 1; then
    AC_CHECK_HEADERS([bfd.h], DEF_BW_HAS_BFD=1)
fi

DEF_BW_HAS_UNWIND=0
DEF_BW_HAS_BACKTRACE=0

BACKTRACE_OK=0

AC_CHECK_HEADERS([unwind.h], DEF_BW_HAS_UNWIND=1)
AC_CHECK_HEADERS([execinfo.h], DEF_BW_HAS_BACKTRACE=1)

if test "$DEF_BW_HAS_UNWIND" -eq 1; then
    BACKTRACE_WARNING="yes - Full debug info available on crash, using unwind"
    AC_DEFINE(BACKWARD_HAS_UNWIND, 1, unwind stack support)
    AC_DEFINE(BACKWARD_HAS_BACKTRACE, 0, no backtrace stack support)
    BACKTRACE_OK=1
elif test "$DEF_BW_HAS_BACKTRACE" -eq 1; then
    BACKTRACE_WARNING="yes - Full debug info available on crash, using backtrace"
    AC_DEFINE(BACKWARD_HAS_BACKTRACE, 1, backtrace stack support)
    BACKTRACE_OK=1
else
    BACKTRACE_OK=0
    BACKTRACE_WARNING="no - Backtraces will not be available on crashes"
    AC_DEFINE(DISABLE_BACKWARD, 1, cannot support backtrace dumping)
fi

if test "$BACKTRACE_OK" -eq 1; then
    # Libdw is the best support
    if test "$DEF_BW_HAS_LIBDW" -eq 1; then
        AC_DEFINE(BACKWARD_HAS_DW, 1, libdl for stack printing)
        LIBS="$LIBS -ldw"
    elif test "$DEF_BW_HAS_BFD" -eq 1; then
        AC_DEFINE(BACKWARD_HAS_BFD, 1, libbfd for stack printing)
        LIBS="$LIBS -lbfd"
    elif test "$DEF_BW_HAS_BACKTRACE" -eq 1; then
        AC_DEFINE(BACKWARD_HAS_BACKTRACE_SYMBOL, 1, backtrace stack support)
        BACKTRACE_WARNING="partial - Missing libdw or libbfd will not print full stacks on crash"
    else
        BACKTRACE_OK=0
        BACKTRACE_WARNING="no - Backtraces will not be available on crashes"
        AC_DEFINE(DISABLE_BACKWARD, 1, cannot support backtrace dumping)
    fi
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME
AC_STRUCT_TM

# Checks for library functions.
AC_HEADER_STDC
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_CHECK_FUNCS([gettimeofday memset select socket strcasecmp strftime strstr])

# Do we have getopt_long natively?
AC_MSG_CHECKING([for system-level getopt_long()])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
		#include <stdio.h>
		#include <unistd.h>
		#ifdef HAVE_GETOPT_H
		#include <getopt.h>
		#endif
		]], [[
		static struct option long_options[] = {   /* options table */
			   { "null-arg", required_argument, 0, 'n' },
			   { 0, 0, 0, 0 }
		};

		int s;
		int option_index;
		int argc;
		char **argv;

		s = getopt_long(argc, argv, "n:", long_options, &option_index);

		]])],[sys_getopt=yes],[sys_getopt=no])
if test "$sys_getopt" = "yes"; then
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_GETOPT_LONG, 1, system defines getopt_long)
else
	AC_MSG_RESULT([no])
fi

# Look for something to define standard int types
stdint=yes
AC_CHECK_HEADER([stdint.h],
	AC_DEFINE(HAVE_STDINT_H, 1, stdint.h is present) stdint=yes,
	stdint=no)

if test "$stdint" = "no"; then
    inttypes=no
	AC_CHECK_HEADER([inttypes.h],
		AC_DEFINE(HAVE_INTTYPES_H, 1, inttypes.h is present) inttypes=yes,
		inttypes=no)
fi

if test "$stdint" = "no"; then
	if test "$inttypes" = "no"; then
		AC_MSG_RESULT([failed])
		AC_MSG_ERROR(could not find stdint.h or inttypes.h.)
	fi
fi

# How does accept() work on this system?
AC_MSG_CHECKING([for accept() addrlen type])
OCFL="$CFLAGS"
CFLAGS="-Werror $CFLAGS"
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
		#include <stdio.h>
		#include <netdb.h>
		#include <sys/types.h>
		#include <sys/socket.h>
		]], [[
		int s = 0;
		struct sockaddr *addr = NULL;
		socklen_t *addrlen = NULL;

		accept(s, addr, addrlen);
		return 0;
		]])],[accept_socklen=yes],[accept_socklen=no])
if test "$accept_socklen" = "yes"; then
	AC_MSG_RESULT([socklen_t])
	AC_DEFINE(HAVE_SOCKLEN_T, 1, accept() takes type socklen_t for addrlen)
else
	AC_MSG_RESULT([int])
fi
CFLAGS="$OCFL"

# Do we have large file support?
AC_SYS_LARGEFILE

# Do we need to use -ldl?
usedl=0
AC_CHECK_LIB([dl], [dlopen],
			usedl=1,
			 AC_MSG_WARN([libdl doesn't seem to be needed on this system]))

if test "$usedl" -eq 1; then
	LIBS="$LIBS -ldl"
	CLIENTCLIBS="$CLIENTCLIBS -ldl"
fi

# We need libz
AC_CHECK_LIB([z], [deflate],
             usez=1,
             AC_MSG_ERROR([libz is required and could not be found]))
LIBS="$LIBS -lz"

# We need threads
ACX_PTHREAD
KSLIBS="$KSLIBS $PTHREAD_LIBS"
CPPFLAGS="$CPPFLAGS $PTHREAD_CFLAGS"

AC_MSG_CHECKING([for pthread_mutex_timedlock])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
                #include <stdio.h>
                #include <pthread.h>
                ]], [[
                     pthread_mutex_timedlock(NULL, NULL);
                     return 0;
                     ]])], [have_timedlock=yes], 
                     [have_timedlock=no])
if test "$have_timedlock" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE(HAVE_PTHREAD_TIMELOCK, [1], [have pthread timelock])
else
    AC_MSG_RESULT([no])
fi

OCPPFLAGS=$CPPFLAGS
CPPFLAGS="$CPPFLAGS -fopenmp"
OLDFLAGS=$LDFLAGS
LDFLAGS="$CPPFLAGS -fopenmp"

AC_MSG_CHECKING([for __gnu_parallel extensions])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
                #include <vector>
                #include <parallel/algorithm>
                ]], [[
                std::vector<int> m;
                __gnu_parallel::sort(m.begin(), m.end());
                return 0;
                ]])], [have_gnuparallel=yes], 
                [have_gnuparallel=no])
if test "$have_gnuparallel" = "yes"; then
    AC_MSG_RESULT([yes])
    AC_DEFINE(HAVE_GNU_PARALLEL, [1], [have __GNU_PARALLEL extensions])
else
    AC_MSG_RESULT([no])
    CPPFLAGS=$OCPPFLAGS
    LDFLAGS=$OLDFLAGS
fi

# Do we need libm for math functions?
AC_MSG_CHECKING([for libm math function in std libs])
OCFL="$CFLAGS"
CFLAGS="-Werror $CFLAGS"
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
		#include <stdio.h>
		#include <math.h>
		]], [[
		double x;
		pow(x, x);
		return 0;
		]])],[needlibm=no],[needlibm=yes])
CFLAGS="$OCFL"
if test "$needlibm" = "yes"; then
	AC_MSG_RESULT([no])
# Do we need to use -lm?
	AC_CHECK_LIB([m], [pow],
				 LIBS="$LIBS -lm",
				 AC_MSG_ERROR([libm is needed and is not available]))
else
	AC_MSG_RESULT([yes])
    LIBMLIB="-lm"
    AC_SUBST(LIBMLIB)
fi

# Do we use libstdc++?
# We need to swap to the g++ compiler here
oCC="$CC"
CC="$CXX"
AC_CHECK_LIB([uClibc++], [main],
			 foundcxxl="uclibc" CXXLIBS="$CXXLIBS -luClibc++")

# Do we use uclibc++?
if test "$foundcxxl"x == "x"; then
	AC_CHECK_LIB([stdc++], [main],
				 foundcxxl="stdc++" CXXLIBS="$CXXLIBS -lstdc++")
fi

if test "$foundcxxl"x == "x" -a "$caponly" -eq 1; then
	AC_MSG_ERROR(Neither uclibc uClibc++ or standard gcc stdc++ libraries found.)
fi
CC="$oCC"
AC_SUBST(CXXLIBS)

AC_MSG_CHECKING([for group 'root'])
if test "`grep -e ^root: /etc/group`" = ""; then
	AC_MSG_RESULT([no.  Using 'wheel'])
	instgrp="wheel"
else
	AC_MSG_RESULT([yes])
	instgrp="root"
fi
AC_SUBST(instgrp)

AC_MSG_CHECKING([for group 'man'])
if test "`grep -e ^man: /etc/group`" = ""; then
	AC_MSG_RESULT([no.  Using '$instgrp'])
	mangrp="$instgrp"
else
	mangrp="man"
fi
AC_SUBST(mangrp)

# We need microhttpd
HAVE_LIBMICROHTTPD=0
AC_CHECK_LIB([microhttpd], [MHD_start_daemon],
             KSLIBS="$KSLIBS -lmicrohttpd" HAVE_LIBMICROHTTPD=1,
             HAVE_LIBMICROHTTPD=0)
if test "$HAVE_LIBMICROHTTPD" -eq 0 -a "$caponly" -eq 0; then
    AC_MSG_ERROR([libmicrohttpd is needed and is not available])
elif test "$HAVE_LIBMICROHTTPD" -eq 1; then
    AC_CHECK_HEADER([microhttpd.h], 
    	AC_DEFINE(HAVE_MICROHTTPD_H, 1, microhttpd is present),
        AC_MSG_ERROR([microhttpd.h is not available check that libmicrohttpd-dev is installed]))
fi

# Check for ncurses for pretty wrapper; no longer mandatory

termcontrol="none";

OLIBS="$LIBS"
AC_CHECK_LIB([ncurses], [initscr],
             AC_DEFINE(HAVE_LIBNCURSES, 1, NCurses terminal lib) \
                 foundlcurses=yes curseaux="-lncurses" termcontrol="ncurses" )

if test "$foundlcurses" != "yes"; then
    AC_CHECK_LIB([curses], [initscr],
                 AC_DEFINE(HAVE_LIBCURSES, 1, Curses terminal lib) \
                     foundlcurses=yes curseaux="-lcurses" termcontrol="curses" )
fi

AC_SEARCH_LIBS([stdscr], tinfo ncurses,curseaux="$curseaux $ac_res")

if test "$foundlcurses" != "yes"; then
    AC_MSG_WARN(Failed to find libcurses or libncurses. Kismet will be compiled without the pretty wrapper)
fi

if test "$termcontrol" = "ncurses"; then
    AC_CHECK_HEADER([ncurses.h], [foundhcurses=yes])
else
    AC_CHECK_HEADER([curses.h], [foundhcurses=yes])
fi

if test "$foundhcurses" != "yes"; then
    AC_MSG_WARN(Failed to find curses.h or ncurses.h.  You probably need to install the curses-devel package from your distribution)
fi

KSLIBS="$KSLIBS $curseaux"

# TODO - check for advanced curses stuff here like cdk/panels

# Check for process title manipulation stuff, from proftpd configure.in
AC_CHECK_FUNCS(setproctitle)
AC_CHECK_HEADERS(libutil.h)
AC_CHECK_LIB(util, setproctitle,
	[AC_DEFINE(HAVE_SETPROCTITLE)
		ac_cv_func_setproctitle="yes" ; LIBS="$LIBS -lutil"])

if test "$ac_cv_func_setproctitle" = "yes"; then
  AC_DEFINE(PF_ARGV_TYPE, PF_ARGV_NONE)
else
  pf_argv_set="no"

  AC_CHECK_HEADERS(sys/pstat.h,have_pstat_h="yes",have_pstat_h="no")
  if test "$have_pstat_h" = "yes"; then
    AC_CHECK_FUNCS(pstat)

    if test "$ac_cv_func_pstat" = "yes"; then
	AC_DEFINE(PF_ARGV_TYPE, PF_ARGV_PSTAT, pstat argv type)
    else
	AC_DEFINE(PF_ARGV_TYPE, PF_ARGV_WRITEABLE, writeable argv type)
    fi

    pf_argv_set="yes"
  fi

  if test "$pf_argv_set" = "no"; then
    AC_EGREP_HEADER([#define.*PS_STRINGS.*],sys/exec.h,
			have_psstrings="yes",have_psstrings="no")
    if test "$have_psstrings" = "yes"; then
	AC_DEFINE(PF_ARGV_TYPE, PF_ARGV_PSSTRINGS)
	pf_argv_set="yes"
    fi
  fi

  if test "$pf_argv_set" = "no"; then
    AC_CACHE_CHECK(whether __progname and __progname_full are available,
		    pf_cv_var_progname,
		    AC_TRY_LINK([extern char *__progname, *__progname_full;],
			[__progname = "foo"; __progname_full = "foo bar";],
			pf_cv_var_progname="yes", pf_cv_var_progname="no"))

    if test "$pf_cv_var_progname" = "yes"; then
	AC_DEFINE(HAVE___PROGNAME, 1, __PROGNAME glibc macro available)
    fi

    AC_CACHE_CHECK(which argv replacement method to use,
		    pf_cv_argv_type,
		    AC_EGREP_CPP(yes,[
#if defined(__GNU_HURD__)
  yes
#endif
  ],pf_cv_argv_type="new", pf_cv_argv_type="writeable"))

    if test "$pf_cv_argv_type" = "new"; then
	AC_DEFINE(PF_ARGV_TYPE, PF_ARGV_NEW, new argv type)
	pf_argv_set="yes"
    fi

    if test "$pf_argv_set" = "no"; then
	AC_DEFINE(PF_ARGV_TYPE, PF_ARGV_WRITEABLE, writeable argv type)
    fi
  fi
fi

# Allow disabling mutex timeout, use with caution
AC_ARG_ENABLE(mutextimeout,
	[  --disable-mutextimeout  disable failsafe mutex lock timeout],
	[case "${enableval}" in
	  no) wantmutex=0 ;;
	   *) wantmutex=1 ;;
	 esac],
	[wantmutex=1]
)

if test "$wantmutex" -eq 0; then
    AC_DEFINE(DISABLE_MUTEX_TIMEOUT, 1, [Remove mutex deadlock timeout protection])
fi

linux_wireless="no"

# Check for linux headers if we're on linux systems
if test "$linux" = "yes"; then

AC_ARG_WITH(linuxheaders,
	[  --with-linuxheaders[=DIR]     Custom location of the Linux kernel headers if the glibc copies are insufficient ],
	[
   	 if test "$withval" != no -a "$withval" != "yes"; then
        CPPFLAGS="$CPPFLAGS -I$withval"
    fi
	])

AC_ARG_ENABLE(linuxwext,
	[  --disable-linuxwext     disable Linux wireless extensions],
	[case "${enableval}" in
	  no) wantwext=no ;;
	   *) wantwext=yes ;;
	 esac],
	[wantwext=yes]
)

linux_wireless="no"

if test "$wantwext" = "yes"; then
	AC_CHECK_HEADER([linux/wireless.h],
		[foundwexth=yes],,
		[
		#include <sys/types.h>
		#include <netdb.h>
		#include <linux/socket.h>
		#include <asm/types.h>
		#include <linux/if.h>
		])

	if test "$foundwexth" != "yes"; then
		AC_MSG_ERROR(Failed to find a usable linux/wireless.h header for Linux Wireless Extensions.  Either your kernel headers are missing or are incorrect.  See config.log for the exact error.  Compiling without wireless headers must be explicitly disabled)
	fi

    AC_MSG_CHECKING(that linux/wireless.h is what we expect)
    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
        #include <stdio.h>
		#include <sys/types.h>
		#include <netdb.h>
		#include <netinet/in.h>
        #include <sys/resource.h>
		#include <asm/types.h>
		#include <linux/if.h>
		#include <linux/wireless.h>
    ]], [[
		struct iwreq wrq;

		wrq.u.essid.flags = 0;
    ]])],[foundwextok=yes])

	if test "$foundwextok" != "yes"; then
		AC_MSG_RESULT(no)
		AC_MSG_ERROR(Failed to find a usable linux/wireless.h header for Linux Wireless Extensions.  Either your kernel headers are missing or are incorrect.  See config.log for the exact error.)
	fi # wexth

	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_LINUX_WIRELESS, 1, Linux wireless extentions present)
	linux_wireless="yes";

	if test "$linux_wireless" = "yes"; then
		iwfreqflag=no
		AC_MSG_CHECKING(can we use iw_freq.flags)
		AC_LINK_IFELSE([AC_LANG_PROGRAM([[
			#include <stdio.h>
			#include <sys/types.h>
			#include <netinet/in.h>
			#include <asm/types.h>
			#include <linux/if.h>
			#include <linux/wireless.h>
		]], [[
			struct iwreq wrq;
			wrq.u.freq.flags = IW_FREQ_FIXED;
		]])],[iwfreqflag=yes],[iwfreqflag=no])

		if test "$iwfreqflag" = "no"; then
			AC_MSG_RESULT(no)
		else
			AC_MSG_RESULT(yes)
			AC_DEFINE(HAVE_LINUX_IWFREQFLAG, 1, [Linux wireless iwfreq.flag])
		fi
	fi

fi # want headers

fi # linux

# Look for capability support
havecap="yes"
AC_CHECK_LIB([cap], [cap_init],,havecap=no)
AC_CHECK_HEADER([sys/prctl.h],, havecap=no)
AC_CHECK_HEADER([sys/capability.h],, havecap=no)

if test "$havecap" = "yes"; then
AC_DEFINE(HAVE_CAPABILITY, 1, kernel capability support)
caplibs="-lcap"
AC_SUBST(caplibs)
fi

AC_ARG_WITH(pcreheaders,
	[  --with-pcreheaders[=DIR]      Custom location of the PCRE library headers ],
	[
   	 if test "$withval" != no -a "$withval" != "yes"; then
        CPPFLAGS="$CPPFLAGS -I$withval"
    fi
	])

AC_ARG_ENABLE(pcre,
	[  --disable-pcre          disable building pcre components],
	[case "${enableval}" in
	  no) wantpcre=no ;;
	   *) wantpcre=yes ;;
	 esac],
	[wantpcre=yes]
)

if test "$wantpcre" = "yes"; then
	# Check for pcre
	pcrel=no
	AC_CHECK_LIB([pcre], [pcre_compile], pcrel=yes, pcrel=no)

	if test "$pcrel" != "yes"; then
		AC_MSG_WARN(Failed to find libpcre)
		wantpcre=no
	fi

	if test "$wantpcre" = "yes"; then
	pcreh=no
	AC_CHECK_HEADER([pcre.h], pcreh=yes, pcreh=no)

	if test "$pcreh" != "yes"; then
		AC_MSG_WARN(Failed to find pcre headers check that the pcre-devel package is installed if your distribution provides separate packages)
		wantpcre=no
	fi
	fi # wantpcre

	if test "$wantpcre" = "yes"; then
	AC_DEFINE(HAVE_LIBPCRE, 1, libpcre regex support)
	LIBS="$LIBS -lpcre"
	fi # pcre
fi

AC_ARG_ENABLE(sqlite3,
	[  --disable-sqlite3       disable building sqlite3 logging],
	[case "${enableval}" in
	  no) wantsql3=no ;;
	   *) wantsql3=yes ;;
	 esac],
	[wantsql3=yes]
)

if test "$wantsql3" = "yes"; then
	# Check for sqlite3
	sql3l=no
	AC_CHECK_LIB([sqlite3], [sqlite3_libversion], sql3l=yes, sql3l=no)

	if test "$sql3l" != "yes"; then
		AC_MSG_WARN(Failed to find libsqlite3)
		wantsql3=no
	fi

	if test "$wantsql3" = "yes"; then
	sql3h=no
	AC_CHECK_HEADER([sqlite3.h], sql3h=yes, sql3h=no)

	if test "$sql3h" != "yes"; then
		AC_MSG_WARN(Failed to find sqlite3 headers check that the libsqlite3-devel package is installed if your distribution provides separate packages)
		wantsql3=no
	fi
	fi # wantsql3

	if test "$wantsql3" = "yes"; then
	AC_DEFINE(HAVE_LIBSQLITE3, 1, libsqlite3 database support)
	LIBS="$LIBS -lsqlite3"
	fi # sqlite3
fi

# Handle airpcap/winpcap on cygwin
if test "$cygwin" = yes; then
AC_CHECK_HEADERS([windows.h Win32-Extensions.h])

AC_ARG_ENABLE(airpcap,
	[  --enable-airpcap        enable checking for CACE airpcap],
	[case "${enableval}" in
	 yes) want_airpcap=yes ;;
	   *) want_airpcap=no ;;
	 esac],
	[want_airpcap=yes]
)

if test "$want_airpcap" = "yes"; then
airpcap_devpack="Airpcap_Devpack"
AC_ARG_WITH(airpcap-devpack,
[  --with-airpcap[=DIR]     Location of the CACE AirPcap device pack NOTE cygwin appears to have link errors if the path is not within the current directory],
[ airpcap_devpack="$withval" ])

# Set the libs and includes
LDFLAGS="$LDFLAGS -L$airpcap_devpack/Lib"
CPPFLAGS="$CPPFLAGS -I$airpcap_devpack/Include"
fi # want_airpcap

winpcap_devpack="Winpcap_Devpack"
AC_ARG_WITH(winpcap-devpack,
[  --with-winpcap[=DIR]     Location of the WinPcap device pack NOTE cygwin appears to have link errors if the path is not within the current directory],
[ winpcap_devpack="$withval" ])

# Set the libs and includes
LDFLAGS="$LDFLAGS -L$winpcap_devpack/Lib"
CPPFLAGS="$CPPFLAGS -I$winpcap_devpack/Include"

fi # cygwin

AC_ARG_ENABLE(prelude,
              AS_HELP_STRING([--enable-prelude],
                             [Enable Prelude SIEM as a target for alerts.]),
[
  wantprelude=no
  if test "$enableval" != "no"; then
    AM_PATH_LIBPRELUDE(1.2.6, , AC_MSG_ERROR(Cannot find libprelude: Is libprelude-config in the path?), no)
    CPPFLAGS="${CPPFLAGS} ${LIBPRELUDE_CFLAGS}"
    LDFLAGS="${LDFLAGS} ${LIBPRELUDE_LDFLAGS}"
    LIBS="${LIBS} ${LIBPRELUDE_LIBS}"
    AC_DEFINE([PRELUDE], [1], [Libprelude support enabled])
    wantprelude=yes
  fi
],[wantprelude=no])

AC_ARG_ENABLE(pcap,
	[  --disable-pcap          disable libpcap (most sources) capture support],
	[case "${enableval}" in
	  no) wantpcap=no ;;
	   *) wantpcap=yes ;;
	 esac],
	[wantpcap=yes]
)
AC_SUBST(wantpcap)

if test "$wantpcap" = yes; then
	foundsyspcap=no

	if test "$cygwin" = yes; then
		pcaplib="wpcap";
	else
		pcaplib="pcap";
	fi

	AC_CHECK_LIB([${pcaplib}], [pcap_open_live],
	    AC_DEFINE(HAVE_LIBPCAP, 1, libpcap packet capture lib) foundsyspcap=yes,
	    AC_MSG_WARN(Compiling without libpcap support.))

	if test "$foundsyspcap" = yes; then
	## if we don't have a pcap.h, do a search for pcap/pcap.h
	AC_CHECK_HEADER([pcap.h],
		AC_DEFINE(HAVE_PCAP_H, 1, libpcap header) foundsyspcaph=yes)
	    if test "$foundsyspcaph" != yes; then
			AC_CHECK_HEADER([pcap/pcap.h],
			AC_DEFINE(HAVE_PCAP_H, 1, libpcap header) AC_DEFINE(HAVE_PCAPPCAP_H, 1, pcap/pcap.h),
			AC_MSG_ERROR([found libpcap but unable to find pcap.h]))
	    fi
	# Look for the new PCAP stuff
	AC_CHECK_LIB([pcap], [pcap_setnonblock],
	    AC_DEFINE(HAVE_PCAP_NONBLOCK, 1, Nonblocking-capable libpcap),
	    AC_MSG_WARN(*** You don't appear to have a version of libpcap which supports non-blocking IO.  We'll fake it, but you REALLY should upgrade your libpcap, as it may not support 802.11 capture sources, either. ***))

	if test "$cygwin" != yes; then
	AC_CHECK_LIB([${pcaplib}], [pcap_get_selectable_fd],
		AC_DEFINE(HAVE_PCAP_GETSELFD, 1, Selectablefd-capable libpcap),
		AC_MSG_ERROR(installed libpcap version does not support features Kismet requires.  Upgrade to a current version of libpcap))
	else
	AC_CHECK_LIB([${pcaplib}], [pcap_fileno],
		AC_DEFINE(HAVE_PCAP_FILENO, 1, pcapfileno-capable libwpcap),
		AC_MSG_ERROR(installed libpcap version does not support features Kismet requires.  Upgrade to a current version of libwpcap))
	fi

	# Look for PPI support in pcap
	AC_MSG_CHECKING([for PPI support in libpcap])
	OCFL="$CFLAGS"
	CFLAGS="-Werror $CFLAGS"
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[
			#include <stdio.h>
			#include <pcap.h>
			]], [[
			return DLT_PPI==DLT_PPI;
			]])],[haveppi=yes],[haveppi=no])
	CFLAGS="$OCFL"
	if test "$haveppi" = "yes"; then
		AC_MSG_RESULT([yes])
		AC_DEFINE(HAVE_PPI, 1, libpcap supports PPI)
	else
		AC_MSG_RESULT([no])
	fi

	pcaplnk="-l${pcaplib}"
	AC_SUBST(pcaplnk)
	pcap="yes"

    DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_PCAPFILE)"
    BUILD_CAPTURE_PCAPFILE=1

    if test "$linux" = "yes"; then
        DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_LINUX_WIFI)"
        BUILD_CAPTURE_LINUX_WIFI=1
    fi

	fi
fi

if test "$wantpcap" = "yes" -a "$pcap" != "yes"; then
	AC_MSG_ERROR(Could not find working libpcap.  Libpcap is vital for the majority of capture sources Kismet supports.  It must be explicitly disabled.)
fi

if test "$wantpcap" != "yes" -o "$pcap" != "yes"; then
    AC_MSG_WARN(Compiling without libpcap support.  Most capture sources will be disabled, this is almost certainly not what you want..)
fi
AC_SUBST(pcap)

if test "$pcap" = "no" -a "$want_airpcap" = "yes"; then
	AC_MSG_WARN([*** Disabling AirPcap, libpcap not enabled ***]);
	want_airpcap=no;
fi

airpcaplib=""
if test "$want_airpcap" = "yes" -a "$pcap" = "yes"; then
	foundairpcap=no
	AC_CHECK_LIB([airpcap], [AirpcapSetLinkType],
	    AC_DEFINE(HAVE_LIBAIRPCAP, 1, libairpcap win32 control lib) foundairpcap=yes,
	    AC_MSG_WARN(Compiling without airpcap support.))

	if test "$foundairpcap" = yes; then
	## if we don't have a pcap.h, do a search for pcap/pcap.h
	AC_CHECK_HEADER([airpcap.h],
		AC_DEFINE(HAVE_AIRPCAP_H, 1, libairpcap header) foundairpcaph=yes)
	fi

	if test "$foundairpcap" != "yes" -o "$foundairpcaph" != "yes"; then
		AC_MSG_WARN(Compiling without airpcap support)
	else
		airpcap="yes"
        airpcaplib = "-lairpcap"
	fi
fi
AC_SUBST(airpcaplib)

if test "$bsd" = yes; then
	AC_MSG_CHECKING(for BSD net80211/radiotap support)
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[
	    #include <stdio.h>
            #include <sys/types.h>
	    #include <sys/socket.h>
	    #include <net/if.h>
	    #include <net/if_media.h>
	    #include <net80211/ieee80211_radiotap.h>
	]], [[

	]])],radiotap=yes bsdradiotap=yes, bsdradiotap=no radiotap=no)
	AC_MSG_RESULT($bsdradiotap)
else
	AC_MSG_WARN(Using local radiotap headers)
fi

if test "$radiotap" != "yes"; then
    AC_DEFINE(HAVE_LOCAL_RADIOTAP, 1, local radiotap packet headers)
	radiotaploc="local"
fi

if test "$bsdradiotap" = "yes"; then
	AC_DEFINE(HAVE_BSD_SYS_RADIOTAP, 1, BSD radiotap packet headers)
	radiotaploc="system (BSD)"
fi

# havenetlink=no
if test "$linux" = "yes"; then
AC_CHECK_PROG(havepkgconfig, [pkg-config], yes, no)
if test "$havepkgconfig" = "no"; then
  AC_MSG_WARN(Missing pkg-config will lead to multiple other checks failing)
fi

NMLIBS=""
NMCFLAGS=""

PKG_CHECK_MODULES(libnm, [libnm], havelibnm=yes, havelibnm=no)
if test $havelibnm = yes; then
    NMLIBS=`pkg-config --libs libnm`
    NMCFLAGS=`pkg-config --cflags libnm`
fi

if test "$havelibnm" = "yes"; then
	OLIBS="$LIBS"
	LIBS="$LIBS $NMLIBS"
	OCPPFL="$CPPFLAGS"
	CPPFLAGS="$CPPFLAGS $NMCFLAGS"

	AC_MSG_CHECKING(For nm_device_set_managed in libnm)
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[
            #include <libnm/NetworkManager.h>
            #include <glib.h>
			]], [[
            nm_device_set_managed(NULL, 0);
			return 0;
			]])],[havelibnm=yes],[havelibnm=no])

	LIBS="$OLIBS"
    CPPFLAGS="$OCPPFL"
else
	AC_MSG_WARN(Libnm missing device_set_managed function, looks like a very old version)
	havelibnm=no
    NMLIBS=""
    NMCFLAGS=""
fi

if test $havelibnm = yes; then
    AC_DEFINE(HAVE_LIBNM, 1, NetworkManager interface library)
fi

AC_SUBST(NMLIBS)
AC_SUBST(NMCFLAGS)

NLLIBS=""
NLCFLAGS=""
nlname=""

havenetlink=yes
netlink_force=no

AC_ARG_WITH(netlink-tiny,
	[  --with-netlink-tiny                       Force libnl-tiny ],
	[
	netlink_force="tiny"
	])

if test "$havenetlink" = "yes"; then
	PKG_CHECK_MODULES(libnl30, [libnl-3.0], libnl30=yes, libnl30=no)
	PKG_CHECK_MODULES(libnlgenl30, [libnl-genl-3.0], libnlgenl30=yes, libnlgenl30=no)
	PKG_CHECK_MODULES(libnl20, [libnl-2.0], libnl20=yes, libnl20=no)
	PKG_CHECK_MODULES(libnl1, [libnl-1], libnl1=yes, libnl1=no)

	picked_nl=no

    if test $netlink_force = "tiny"; then
        picked_nl="tiny"
        AC_CHECK_HEADER([netlink/netlink.h], 
                AC_DEFINE(HAVE_LIBNLTINY_HEADERS, 1, [libnltiny headers present]), 
                AC_MSG_ERROR([libnl-tiny requested but could not find headers]))

        AC_DEFINE(HAVE_LIBNL, 1, libnl netlink library)
        AC_DEFINE(HAVE_LIBNLTINY, 1, libnl-2.0 netlink library)
        nlname="libnl-tiny"
    fi

	if test $picked_nl = "no" -a "$libnl30" = "yes" -a "$libnlgenl30" = "yes"; then
		if test $netlink_force = "no" -o $netlink_force = "3"; then
			picked_nl=3
			AC_DEFINE(HAVE_LIBNL, 1, libnl netlink library)
			AC_DEFINE(HAVE_LIBNL30, 1, libnl-3.0 netlink library)
			nlname="libnl-3.0 libnl-genl-3.0"
		fi
	fi

	if test $picked_nl = "no" -a "$libnl20" = "yes"; then
		if test $netlink_force = "no" -o $netlink_force = "2"; then
			picked_nl=2
			AC_DEFINE(HAVE_LIBNL, 1, libnl netlink library)
			AC_DEFINE(HAVE_LIBNL20, 1, libnl-2.0 netlink library)
			nlname="libnl-2.0"
		fi
	fi

	if test $picked_nl = "no" -a "$libnl1" = "yes"; then
		if test $netlink_force = "no" -o $netlink_force = "1"; then
			picked_nl=1
			AC_DEFINE(HAVE_LIBNL, 1, libnl netlink library)
			AC_DEFINE(HAVE_LIBNL10, 1, libnl netlink library)
			nlname="libnl-1"
		fi
	fi

	if test $picked_nl = "no"; then
		havenetlink="no"
	fi

	if test "$nlname" != ""; then
        if test "$picked_nl" == "tiny"; then
            NLLIBS="-lnl-tiny"
        else
		    NLLIBS=`pkg-config --libs $nlname`
		    NLCFLAGS=`pkg-config --cflags $nlname`
        fi
	fi
fi

if test "$havenetlink" = "yes"; then
	OLIBS="$LIBS"
	LIBS="$LIBS $NLLIBS"
	OCPPFL="$CPPFLAGS"
	CPPFLAGS="$CPPFLAGS $NLCFLAGS"

	AC_MSG_CHECKING(For mac80211 support in netlink library)
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[
			#include <stdio.h>
			#include <asm/types.h>
			#include <netlink/genl/genl.h>
			#include <netlink/genl/family.h>
			#include <netlink/genl/ctrl.h>
			#include <netlink/msg.h>
			#include <netlink/attr.h>
			#include <linux/nl80211.h>
			#include <linux/if_arp.h>
			#include <linux/wireless.h>
			]], [[
			NL80211_IFTYPE_MONITOR;
			NL80211_CMD_NEW_INTERFACE;
			return 0;
			]])],[havenetlink=yes],[havenetlink=no])

	LIBS="$OLIBS"
	CPPFLAGS="$OCPPFL"
else
	AC_MSG_WARN(Missing libnl netlink library will not be able to control mac80211 vaps)
	havenetlink=no
fi

if test "$havenetlink" = "yes"; then
	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_LINUX_NETLINK, 1, Netlink works)
fi

fi

AC_SUBST(NLLIBS)
AC_SUBST(NLCFLAGS)

if test "$linux" = "yes"; then
    BUILD_CAPTURE_LINUX_BLUETOOTH=1
    DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_LINUX_BLUETOOTH)"
fi

if test "$darwin" = "yes"; then
	suidgroup="staff"
else
	suidgroup="kismet"
fi
AC_ARG_WITH(suidgroup,
	[  --with-suidgroup=group       Group allowed to execute the kismet_capture suid root helper process ],
	[
   	 if test "$withval"x != "x"; then
	 	suidgroup="$withval"
     fi
	])
AC_SUBST(suidgroup)

# Evaluate suid
if test "$cygwin" = "yes"; then
	suid="no"
fi


# We include GPS handling code regardless, for now.
AC_DEFINE(HAVE_GPS, 1, GPS support will be built.)

AC_ARG_ENABLE(optimization,
	[  --disable-optimization        disable -Ox gcc optimization],
	[case "${enableval}" in
	  no) wantopto=no ;;
	   *) wantopto=yes ;;
	 esac],
	[wantopto=yes]
)
if test "$wantopto" != "yes"; then
	CPPFLAGS=`echo $CPPFLAGS | sed -e 's/-O.//g'`
	CXXFLAGS=`echo $CXXFLAGS | sed -e 's/-O.//g'`
fi

AC_ARG_ENABLE(asan,
	[  --enable-asan           enable ASAN address debugging],
	[case "${enableval}" in
	 yes) want_asan=yes ;;
	   *) want_asan=no ;;
	 esac],
	[want_asan=no]
)
if test "$want_asan" == "yes"; then
    CPPFLAGS="$CPPFLAGS -fsanitize=address"
    LDFLAGS="$LDFLAGS -fsanitize=address"
fi

AC_ARG_ENABLE(tsan,
	[  --enable-tsan           enable thread-sanitizer debugging],
	[case "${enableval}" in
	 yes) want_tsan=yes ;;
	   *) want_tsan=no ;;
	 esac],
	[want_tsan=no]
)
if test "$want_tsan" == "yes"; then
    CPPFLAGS="$CPPFLAGS -fsanitize=thread"
    LDFLAGS="$LDFLAGS -fsanitize=thread"
fi

AC_SUBST(KSLIBS)

sharedatadir=$datadir
sharedatadir=`(
    test "$prefix" = NONE && prefix=$ac_default_prefix
    test "$exec_prefix" = NONE && exec_prefix=${prefix}
    eval echo "$sharedatadir"
)`
sharedatadir=${sharedatadir}
AC_SUBST(sharedatadir)

CPPFLAGS="$CPPFLAGS -I$BUNDLE_MSGPACK/include"

AC_SUBST(DATASOURCE_BINS)
AC_SUBST(BUILD_CAPTURE_PCAPFILE)
AC_SUBST(BUILD_CAPTURE_LINUX_WIFI)
AC_SUBST(BUILD_CAPTURE_HACKRF_SWEEP)
AC_SUBST(BUILD_CAPTURE_LINUX_BLUETOOTH)

#AC_SUBST(CPPFLAGS)
#AC_SUBST(CFLAGS)
#AC_SUBST(CXXFLAGS)

AC_CONFIG_FILES([Makefile Makefile.inc scripts/kismet conf/kismet.conf packaging/kismet.pc capture_linux_bluetooth/Makefile capture_linux_wifi/Makefile])
AC_OUTPUT

echo
echo "Configuration complete: "
echo "         Compiling for: $host_os ($host_cpu)"
echo "           C++ Library: $foundcxxl"
echo "   Installing as group: $instgrp"
echo "    Man pages owned by: $mangrp"
echo "       Installing into: $prefix"
printf "          Setuid group: "
if test "$cygwin" = "yes"; then
	echo "n/a (Cygwin/Win32";
else
	echo "$suidgroup"
fi

printf "      Terminal Control: "
echo "$termcontrol";

printf "   Linux WEXT capture : "
if test "$linux_wireless" = "yes"; then
	echo "yes"
elif test "$linux" != "yes"; then
	echo "n/a (only Linux)"
else
	echo "no"
fi
printf "        Prelude  SIEM : $wantprelude\n"
printf "   OSX/Darwin capture : "
if test "$darwin" = "yes"; then
	echo "yes"
elif test "$darwin" != "yes"; then
	echo "n/a (only OSX/Darwin)"
else
	echo "no"
fi
printf "   PCRE Regex Filters : "
if test "$wantpcre" = "yes"; then
	echo "yes"
else
	echo "no"
fi
printf "          pcap capture: "
if test "$pcap" = "yes"; then
	echo "yes"
else
	echo "no"
fi
printf "       airpcap control: "
if test "$airpcap" = "yes"; then
	echo "yes"
elif test "$cygwin" != "yes"; then
	echo "n/a (only Cygwin/Win32)"
else
	echo "no"
fi
printf "        PPI log format: "
if test "$haveppi" = "yes"; then
	echo "yes"
else
	echo "no - PPI logging unavailable, upgrade libpcap"
fi
printf "LibCapability (enhanced\n"
printf "   privilege dropping): "
if test "$havecap" = "yes"; then
	echo "yes";
elif test "$linux" != "yes"; then
	echo "n/a (only Linux)"
else
	echo "no";
fi

printf "         Linux Netlink: "
if test "$havenetlink" = "yes"; then
	echo "yes (mac80211 VAP creation) - $nlname";
elif test "$linux" != "yes"; then
	echo "n/a (only Linux)"
else
	echo "no (will not be able to make mac80211 vaps)";
fi

printf "  Linux NetworkManager: "
if test "$havelibnm" = "yes"; then
	echo "yes (libnm NetworkManager control)";
elif test "$linux" != "yes"; then
	echo "n/a (only Linux)"
else
	echo "no (will not be able to control NetworkManager)";
fi

printf "       Linux Bluetooth: "
if test "$BUILD_CAPTURE_LINUX_BLUETOOTH" = 1; then
	echo "yes";
elif test "$linux" != "yes"; then
	echo "n/a (only Linux)"
else
	echo "no (will not be able to track Bluetooth on Linux)";
fi

printf "       HackRF spectrum: "
if test "$BUILD_HACKRF_SWEEP" -eq 1; then
	echo "yes (libhackrf and libfftw3 present)";
else
	echo "no ($HACKRF_MISSING_REASON)";
fi

printf "      SQLite3 Database: "
if test "$wantsql3" = "yes"; then
	echo "yes"
else
	echo "no - some logging will not be available"
fi

printf "        Built-in Debug: "
echo $BACKTRACE_WARNING

if test "$havepkgconfig" = "no"; then
	echo
	echo "pkg-config was missing.  Without it, configure cannot detect "
	echo "several libraries Kismet needs.  Install pkg-config and re-run"
	echo "configure."
fi

if test "`echo $host_os | grep linux`" = ""; then
	echo
	echo "Configuration complete.  You are not running a linux-based system,"
	echo "you will likely need to use 'gmake' instead of 'make'."
	echo "Run 'gmake' followed by 'gmake install' to compile and install Kismet"
else
	verminor=`uname -r | cut -d '.' -f 2`
	# Stupid redhat
	vertiny=`uname -r | cut -d '.' -f 3 | cut -f 1 -d-`

	echo
	echo "Configuration complete.  You can now run 'make' to compile kismet, "
    echo "followed by 'make install' or 'make suidinstall' to install it."
fi

if test "$linux_wireless" != "yes" -a "$linux" = "yes"; then
	echo
    echo "*** WARNING ***"
	echo "Linux Wireless Extensions were disabled.  Compiling without wext on a "
	echo "Linux system is certainly possible, however nearly all of the packet "
	echo "sources will be disabled (including capture sources for Cisco, Madwifi, "
	echo "Orinoco, Prism, and just about every other live capture method).  Make "
	echo "sure this is what you want to do."
    echo "*** WARNING ***"
fi

if test "$pcap" != "yes" -a "$linux" = "yes"; then
	echo
	echo "*** WARNING ***"
	echo "LibPCAP was not found."
	echo "Kismet on Linux without LibPcap cannot capture data locally and will "
	echo "almost certainly NOT BE WHAT YOU WANT."
	echo "You need both the libpcap libraries and development headers (called "
	echo "libpcap-dev or libpcap-devel by most distributions)."
fi

if test "$havenetlink" != "yes" -a "$linux" = "yes"; then
	echo
	echo "*** WARNING ***"
	echo "LibNL/nl80211 support was not found.  Kismet uses libnl to control "
	echo "mac80211 based wireless interfaces, which comprise the vast majority of"
	echo "interfaces on modern Linux systems.  Unless you plan to use only "
	echo "older drivers, you need libnl."
	echo "You need both the libnl libraries and development headers (called "
	echo "libnl-dev or libnl-devel by most distributions)."

	if test "$havepkgconfig" = "no"; then
		echo "You do not have the pkg-config utility installed.  Kismet needs "
		echo "this to find the options libnl uses.  If libnl is installed but "
		echo "pkg-config is not, Kismet will not detect libnl!"
	fi
fi

if test "$havelibnm" != "yes" -a "$linux" = "yes"; then
    echo
    echo "*** WARNING ***"
    echo "libnm (the NetworkManager control library) was not found.  Kismet uses "
    echo "libnm to prevent NetworkManager from reconfiguring monitor mode interfaces "
    echo "while Kismet is running; without this library you will need to manually "
    echo "disable NetworkManager or manually tell it to ignore specific interaces."
fi

if test "$want_asan" = "yes" -a "$want_tsan" = "yes"; then
	echo
    echo "*** WARNING ***"
    echo "It is unlikely that enabling both thread sanitization debugging"
    echo "and address sanitizer debugging simultaneously will work due to "
    echo "binary differences.  Likely, the compiler will reject this, "
    echo "but you can try."
elif test "$want_asan" = "yes" -o "$want_tsan" = "yes"; then
    echo 
    echo "*** NOTICE ***"
    echo "Compiling with ASAN or TSAN debugging can greatly increase the "
    echo "amount of RAM Kismet needs; you may see degraded performance or "
    echo "increased system load."
fi


