# Process this file with autoconf to produce a configure script.
AC_INIT

VERSION=$(grep VERSION_MAJOR version.h | cut -d'"' -f 2)-$(grep VERSION_MINOR version.h | cut -d'"' -f 2)-$(grep VERSION_TINY version.h | cut -d'"' -f 2)-$(git rev-parse --short HEAD 2>/dev/null || echo 'non-git-release')
AC_SUBST(VERSION)

#m4_include([m4/acx_pthread.m4])
#m4_include([m4/ax_cxx_compile_stdcxx.m4])
#m4_include([m4/ax_cxx_compile_stdcxx_11.m4])
AC_CONFIG_MACRO_DIR([m4])

AC_CONFIG_SRCDIR([kismet.h])

AC_PREREQ([2.71])

# Check for host type
AC_CANONICAL_HOST

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_CPP

AC_LANG([C++])

BUILD_CAPTURE_LINUX_WIFI=0
BUILD_CAPTURE_LINUX_BLUETOOTH=0
BUILD_CAPTURE_OPENBSD_WIFI=0
BUILD_CAPTURE_PCAPFILE=0
BUILD_CAPTURE_KISMETDB=1
BUILD_CAPTURE_HACKRF_SWEEP=0
BUILD_CAPTURE_OSX_COREWLAN=0
BUILD_CAPTURE_NRF_MOUSEJACK=0
BUILD_CAPTURE_TI_CC_2540=0
BUILD_CAPTURE_TI_CC_2531=0
BUILD_CAPTURE_UBERTOOTH_ONE=0
BUILD_CAPTURE_SDR_RTL433V2=0
BUILD_CAPTURE_SDR_RTLADSBV2=0
BUILD_CATPURE_FREAKLABS_ZIGBEEV2=1
BUILD_CAPTURE_NRF_51822=0
BUILD_CAPTURE_NXP_KW41Z=0
BUILD_CAPTURE_RZ_KILLERBEE=0
BUILD_CAPTURE_BLADERF_WLAN=0
BUILD_CAPTURE_NRF_52840=0
BUILD_CAPTURE_HAK5_COCONUT=0
BUILD_CAPTURE_USB_RADIACODE=0
BUILD_CAPTURE_ANTSDR_DRONEID=1

# deprecated
BUILD_CAPTURE_SDR_RTL433=0
BUILD_CAPTURE_SDR_RTLAMR=0
BUILD_CAPTURE_SDR_RTLADSB=0
BUILD_CAPTURE_BT_GEIGER=0
BUILD_CAPTURE_FREAKLABS_ZIGBEE=0
BUILD_CAPTURE_PROXY_ADSB=0

DATASOURCE_BINS="\$(CAPTURE_KISMETDB)"

BUILD_PYTHON_MODULES=0

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
		openbsd="yes"
		bsd="yes"
		;;
	netbsd*)
		AC_MSG_RESULT(adding pkgsrc locations)
		CPPFLAGS="$CPPFLAGS -I/usr/pkg/include"
		LDFLAGS="$LDFLAGS -L/usr/pkg/lib"
		AC_DEFINE(SYS_NETBSD, 1, Compiling for NetBSD)
		bsd="yes"
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
		openbsd="yes"
		bsd="yes"
        ;;
    netbsd*)
		AC_MSG_RESULT(adding pkgsrc locations)
		CPPFLAGS="$CPPFLAGS -I/usr/pkg/include"
		LDFLAGS="$LDFLAGS -L/usr/pkg/lib"
        AC_DEFINE(SYS_NETBSD, 1, Compiling for NetBSD)
		bsd="yes"
        ;;
    *)
        AC_MSG_RESULT(none needed)
        ;;
    esac

    # Get the GCC version
    AX_GCC_VERSION

    GCC_MAJOR=$(echo $GCC_VERSION | cut -s -d'.' -f1)
    GCC_MINOR=$(echo $GCC_VERSION | cut -s -d'.' -f2)
    GCC_PATCH=$(echo $GCC_VERSION | cut -s -d'.' -f3)

    if test "$GCC_MAJOR"x = x; then
        GCC_MAJOR=$GCC_VERSION
    fi
    if test "$GCC_MINOR"x = x; then
        GCC_MINOR=0
    fi
    if test "$GCC_PATCH"x = x; then
        GCC_PATCH=0
    fi

    AC_DEFINE_UNQUOTED(GCC_VERSION_MAJOR, $GCC_MAJOR, [gcc version])
    AC_DEFINE_UNQUOTED(GCC_VERSION_MINOR, $GCC_MINOR, [gcc version])
    AC_DEFINE_UNQUOTED(GCC_VERSION_PATCH, $GCC_PATCH, [gcc version])

fi

# Start at the newest C++ and define our way back
AX_CXX_COMPILE_STDCXX(20, , [optional])
if test "$HAVE_CXX20" = "1"; then
    AC_DEFINE(HAVE_CXX20, 1, [cpp20 available])
    AC_DEFINE(HAVE_CXX17, 1, [cpp17 available])
    AC_DEFINE(HAVE_CXX14, 1, [cpp14 available])
    AC_DEFINE(HAVE_CXX11, 1, [cpp11 available])
else
    AX_CXX_COMPILE_STDCXX(17, , [mandatory])
    AC_DEFINE(HAVE_CXX17, 1, [cpp17 available])
    AC_DEFINE(HAVE_CXX14, 1, [cpp14 available])
    AC_DEFINE(HAVE_CXX11, 1, [cpp11 available])
# else
#     AX_CXX_COMPILE_STDCXX(14, ,[mandatory])
#     if test "$HAVE_CXX14" = "1"; then
#         AC_DEFINE(HAVE_CXX14, 1, [cpp14 available])
#         AC_DEFINE(HAVE_CXX11, 1, [cpp11 available])
#     fi
fi

# GCC13/14 seem to have over-aggressive/known bad dangling reference detection.
# This gets SUPER noisy in libfmt.
AS_IF([test x"$GCC_MAJOR" = x"13" -o x"$GCC_MAJOR" = x"14"],
    [
        AC_MSG_WARN([setting -Wno-dangling-reference for gcc${GCC_MAJOR}])
        CPPFLAGS="${CPPFLAGS} -Wno-dangling-reference"
    ],
    []
)


AC_SUBST(PLUGINLDFLAGS)

CXXFLAGS="$CXXFLAGS -O3"
CFLAGS="$CFLAGS -O3"

AC_CONFIG_SRCDIR([kismet_server.cc])
AC_CONFIG_HEADERS([config.h])

# Config location for code to default to
CONFFILE_DIR=$sysconfdir
CONFFILE_DIR=`(
    test "$prefix" = NONE && prefix=$ac_default_prefix
    test "$exec_prefix" = NONE && exec_prefix=${prefix}
    eval echo "$CONFFILE_DIR"
)`
AC_DEFINE_UNQUOTED(SYSCONF_LOC, "$CONFFILE_DIR", system config directory)
AC_SUBST(CONFFILE_DIR)

LOCALSTATE_DIR=$localstatedir
LOCALSTATE_DIR=`(
                 test "$prefix" = NONE && prefix=$ac_default_prefix
                 test "$exec_prefix" = NONE && exec_prefix=${prefix}
                 eval echo "$LOCALSTATE_DIR"
                )`
AC_DEFINE_UNQUOTED(LOCALSTATE_DIR, "$LOCALSTATE_DIR", system state directory)
AC_SUBST(LOCALSTATE_DIR)

BIN_DIR=$bindir
BIN_DIR=`(
    test "$prefix" = NONE && prefix=$ac_default_prefix
    test "$exec_prefix" = NONE && exec_prefix=${prefix}
    eval echo "$BIN_DIR"
)`
AC_DEFINE_UNQUOTED(BIN_LOC, "$BIN_DIR", system binary directory)
AC_SUBST(BIN_DIR)

LIB_DIR=$libdir
LIB_DIR=`(
    test "$prefix" = NONE && prefix=$ac_default_prefix
    test "$exec_prefix" = NONE && exec_prefix=${prefix}
    eval echo "$LIB_DIR"
)`
AC_DEFINE_UNQUOTED(LIB_LOC, "$LIB_DIR", system library directory)
AC_SUBST(LIB_DIR)

DATA_DIR=$datarootdir
DATA_DIR=`(
    test "$prefix" = NONE && prefix=$ac_default_prefix
    test "$exec_prefix" = NONE && exec_prefix=${prefix}
    eval echo "$DATA_DIR"
)`
AC_DEFINE_UNQUOTED(DATA_LOC, "$DATA_DIR", system data directory)
AC_SUBST(DATA_DIR)

BASE_DIR=`(
    test "$prefix" = NONE && prefix=$ac_default_prefix
    test "$exec_prefix" = NONE && exec_prefix=${prefix}
    eval echo "$prefix"
)`
AC_SUBST(BASE_DIR)

# Check for endian
AC_C_BIGENDIAN

# Check for brew
want_homebrew=no
AC_ARG_ENABLE([homebrew],
    AS_HELP_STRING([--enable-homebrew], [Automatically enable detecting libraries from homebrew on macOS]),
    [case "${enableval}" in
        yes) want_homebrew=yes ;;
        *) want_homebrew=no ;;
    esac],
    [want_homebrew=no]
)

AS_IF([test x"$want_homebrew" != x"no"],
    [
        AC_MSG_CHECKING([for paths from homebrew])
        AC_MSG_RESULT([ok])

        LDFLAGS="-L`/opt/homebrew/bin/brew --prefix`/lib $LDFLAGS"
        CPPFLAGS="-I`/opt/homebrew/bin/brew --prefix`/include -I`/opt/homebrew/bin/brew --prefix openssl`/include $CPPFLAGS"
        SSL_DIRS=`/opt/homebrew/bin/brew --prefix openssl`
    ],
    []
)

# Enable thread debugging
AC_ARG_ENABLE([mutex-name-debug],
    AS_HELP_STRING([--disable-mutex-name-debug], [Disable naming of mutexes to help in debugging, debugging will use slightly more RAM]),
    [case "${enableval}" in
      no) want_mutex_debugging=no ;;
       *) AC_DEFINE(DEBUG_MUTEX_NAME, 1, Named mutex debugging) ;;
    esac], [AC_DEFINE(DEBUG_MUTEX_NAME, 1, Named mutex debugging)])

# Configure for a remote-capture-only build
caponly=no
AC_ARG_ENABLE(capture-tools-only,
	[  --enable-capture-tools-only  Configure and build for capture tools and remote only],
	[case "${enableval}" in
	  no) caponly=no ;;
	   *) caponly=yes ;;
	 esac],
	[caponly=no]
)

AS_IF([test "$caponly"x = "no"x],
      [
       ALLTARGETS='$(STD_ALL)'
      ],
      [
       ALLTARGETS='$(DS_ONLY)'
      ]
)
AC_SUBST(ALLTARGETS)

want_te_typesafety=no
AC_ARG_ENABLE([element-typesafety],
    AS_HELP_STRING([--enable-element-typesafety], [Enable runtime type safety debugging of the tracked element system]),
    [case "${enableval}" in
      no) want_te_typesafety=no ;;
      *)  want_te_typesafety=yes ;;
  esac],
  [want_te_typesafety=no]
)
AS_IF([test "x$want_te_typesafety" = "xyes"],
      [
       AC_DEFINE(TE_TYPE_SAFETY, 1, Enforce runtime type safety)
      ],
      [
       AC_DEFINE(TE_TYPE_SAFETY, 0, Do not enforce runtime type safety)
      ]
)

want_protobuf=no
AC_ARG_ENABLE([protobuf],
    AS_HELP_STRING([--enable-protobuf], [Enable protobuf support for older remote datasources]),
    [case "${enableval}" in
     yes) want_protobuf=yes ;;
     *) ;;
    esac],
    []
)

PROTOBUF=protobuf
AC_ARG_ENABLE([protobuflite],
    AS_HELP_STRING([--enable-protobuflite], [Force building with protobuf-lite instead of full protobuf]),
    [case "${enableval}" in
     yes) PROTOBUF=protobuf-lite ;;
     *)  ;;
    esac],
    []
)

AS_IF([test "$want_protobuf"x = "yes"x -a "$caponly"x = "yes"x],
      [
       AC_MSG_WARN([protobufs disabled when only building capture tools])
       want_protobuf=no
      ],
      []
)

want_python=no
AC_ARG_ENABLE([python-tools],
    AS_HELP_STRING([--enable-python-tools], [Enable building (legacy) Python modules and Python-only data sources]),
       [case "${enableval}" in
        yes) want_python=yes ;;
          *) want_python=no ;;
        esac],
       [want_python=no]
)

PYTHON=python3
PYTHON_VERSION=3

AC_ARG_WITH([python-interpreter],
    AS_HELP_STRING([--with-python-interpreter=PATH], [Custom location of python interpreter if not in normal PATH]))

AS_IF([test "x$with_python_interpreter" != "x"],
    [
        PYTHON=$with_python_interpreter
    ],
    []
)

AC_SUBST(PYTHON)
AC_SUBST(PYTHON_VERSION)

# HAVE_LIBHACKRF=0
# HAVE_LIBFFTW3=0
# HAVE_HACKRF_H=0
# HAVE_FFTW3_H=0
# BUILD_CAPTURE_HACKRF_SWEEP=0
# HACKRF_MISSING_REASON="Missing required libhack/libfftw3 libraries"
#
# AC_CHECK_HEADERS([libhackrf/hackrf.h],
#     HAVE_HACKRF_H=1,
#     AC_MSG_WARN("Missing hackrf.h from libhackrf"))
# AC_CHECK_HEADERS([fftw3.h],
#     HAVE_FFTW3_H=1,
#     AC_MSG_WARN("Missing fftw3.h from libfftw"))
#
# if test "$HAVE_HACKRF_H" = 1; then
#     AC_CHECK_LIB([hackrf], [hackrf_init],
# 			HAVE_LIBHACKRF=1,
# 			 AC_MSG_WARN([libhackrf not available]))
# else
#     HACKRF_MISSING_REASON="Missing libhackrf/hackrf.h"
# fi
#
# if test "$HAVE_FFTW3_H" = 1; then
#     AC_CHECK_LIB([fftw3], [fftw_malloc],
#             HAVE_LIBFFTW3=1,
#             AC_MSG_WARN([libfftw3 not available]))
# else
#     HACKRF_MISSING_REASON="missing libfftw3.h"
# fi
#
# if test "$HAVE_LIBHACKRF" = 1 && test "$HAVE_LIBFFTW3" = 1; then
#     AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#     		#include <libhackrf/hackrf.h>
#     		]], [[
#             int s = SAMPLES_PER_BLOCK;
#     		return 0;
#     		]])],[hackrfsweep=1],[hackrfsweep=0])
#     if test "$hackrfsweep" = 1; then
#         AC_DEFINE(BUILD_CAPTURE_HACKRF_SWEEP, 1, Able to build hackrf sweep source)
#         # BUILD_CAPTURE_HACKRF_SWEEP=1
#         # DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_HACKRF_SWEEP)"
#     else
#         AC_MSG_WARN([Old version of libhack does not contain sweep code])
#         HACKRF_MISSING_REASON="old version of libhackrf found"
#     fi
# else
#     HACKRF_MISSING_REASON="missing libhackrf or libfftw3"
# fi

HAVE_LIBDW=0
HAVE_LIBBFD=0

# Allow disabling mutex timeout, use with caution
AC_ARG_ENABLE(debuglibs,
    AS_HELP_STRING([--disable-debuglibs], [Disable libdw and bfd libs which aid in debugging]),
	[case "${enableval}" in
	  no) wantdebuglibs=0 ;;
	   *) wantdebuglibs=1 ;;
	 esac],
	[wantdebuglibs=1]
)


if test "$wantdebuglibs" = 1; then
    AC_CHECK_LIB([dw], [dwarf_begin], HAVE_LIBDW=1)
    AC_CHECK_LIB([bfd], [bfd_alloc], HAVE_LIBBFD=1)

    if test "$HAVE_LIBDW" = 1; then
        AC_CHECK_HEADERS([elfutils/libdw.h elfutils/libdwfl.h dwarf.h], DEF_BW_HAS_LIBDW=1)
    fi

    if test "$HAVE_LIBBFD" = 1; then
        AC_CHECK_HEADERS([bfd.h], DEF_BW_HAS_BFD=1)
    fi

    DEF_BW_HAS_UNWIND=0
    DEF_BW_HAS_BACKTRACE=0

    BACKTRACE_OK=0

    AC_CHECK_HEADERS([unwind.h], DEF_BW_HAS_UNWIND=1)
    AC_CHECK_HEADERS([execinfo.h], DEF_BW_HAS_BACKTRACE=1)

    if test "$DEF_BW_HAS_UNWIND" = 1; then
        BACKTRACE_WARNING="yes - Full debug info available on crash, using unwind"
        AC_DEFINE(BACKWARD_HAS_UNWIND, 1, unwind stack support)
        AC_DEFINE(BACKWARD_HAS_BACKTRACE, 0, no backtrace stack support)
        BACKTRACE_OK=1
    elif test "$DEF_BW_HAS_BACKTRACE" = 1; then
        BACKTRACE_WARNING="yes - Full debug info available on crash, using backtrace"
        AC_DEFINE(BACKWARD_HAS_BACKTRACE, 1, backtrace stack support)
        BACKTRACE_OK=1
    else
        BACKTRACE_OK=0
        BACKTRACE_WARNING="no - Backtraces will not be available on crashes"
        AC_DEFINE(DISABLE_BACKWARD, 1, cannot support backtrace dumping)
    fi

    if test "$BACKTRACE_OK" = 1; then
        # Libdw is the best support
        if test "$DEF_BW_HAS_LIBDW" = 1; then
            AC_DEFINE(BACKWARD_HAS_DW, 1, libdl for stack printing)
            LIBS="$LIBS -ldw"
        elif test "$DEF_BW_HAS_BFD" = 1; then
            AC_DEFINE(BACKWARD_HAS_BFD, 1, libbfd for stack printing)
            LIBS="$LIBS -lbfd"
        elif test "$DEF_BW_HAS_BACKTRACE" = 1; then
            AC_DEFINE(BACKWARD_HAS_BACKTRACE_SYMBOL, 1, backtrace stack support)
            BACKTRACE_WARNING="partial - Missing libdw or libbfd will not print full stacks on crash"
        else
            BACKTRACE_OK=0
            BACKTRACE_WARNING="no - Backtraces will not be available on crashes"
            AC_DEFINE(DISABLE_BACKWARD, 1, cannot support backtrace dumping)
        fi
    fi
else
    BACKTRACE_WARNING="no - debug libraries disabled by configure"
    AC_DEFINE(DISABLE_BACKWARD, 1, disabled by configure arguments)
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

# How do we do strerror?
AC_MSG_CHECKING([for strerror_r() return])
AC_LINK_IFELSE([AC_LANG_PROGRAM([
        #include <string.h>
        ], [
            int r;

            r = strerror_r(1, (char *) NULL, 0);
            return 0;
        ])],[strerror_r_int=yes], [strerror_r_int=no])

if test "$strerror_r_int" = "yes"; then
    AC_MSG_RESULT([int])
    AC_DEFINE(STRERROR_R_T, [int], [strerror_r return type])
else
    AC_MSG_RESULT([char *])
    AC_DEFINE(STRERROR_R_T, [char *], [strerror_r return type])
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

# Do we have pipe2?
AC_MSG_CHECKING([for pipe2])
OCFL="$CFLAGS"
CFLAGS="-Werror $CFLAGS"
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
        #include <unistd.h>
		]], [[
        int fd[2], flags;

        pipe2(fd, flags);
		return 0;
		]])],[have_pipe2=yes],[have_pipe2=no])
if test "$have_pipe2" = "yes"; then
	AC_MSG_RESULT([yes])
	AC_DEFINE(HAVE_PIPE2, 1, System has pipe2)
else
	AC_MSG_RESULT(NO)
fi
CFLAGS="$OCFL"

# Do we have large file support?
AC_SYS_LARGEFILE

# Do we need to use -ldl?
usedl=0
AC_CHECK_LIB([dl], [dlopen],
			usedl=1,
			 AC_MSG_WARN([libdl doesn't seem to be needed on this system]))
if test "$usedl" = 1; then
	LIBS="$LIBS -ldl"
	CLIENTCLIBS="$CLIENTCLIBS -ldl"
fi

# We always need libz
AC_CHECK_LIB([z], [deflate],
             usez=1,
             AC_MSG_ERROR([libz is required and could not be found]))
LIBS="$LIBS -lz"

# Do we need -latomic
AC_MSG_CHECKING([for libatomic])
OLIBS="$LIBS"
LIBS="$LIBS -latomic"
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
                ]],
                [[
                 return 0;
                ]] )], [have_atomic=yes], [have_atomic=no])
if test "$have_atomic" = "yes"; then
    AC_MSG_RESULT([yes])
else
    AC_MSG_RESULT([no])
    LIBS="$OLIBS"
fi

# We need threads
PTHREAD_CFLAGS="-pthread"
PTHREAD_LIBS="-lpthread"
AC_SUBST(PTHREAD_CFLAGS)
AC_SUBST(PTHREAD_LIBS)

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
AC_CHECK_LIB([stdc++], [main],
        foundcxxl="stdc++" CXXLIBS="$CXXLIBS -lstdc++")

AS_IF([test "$foundcxxl"x = "x" -a "$caponly"x != "yes"x],
      [
       AC_MSG_ERROR(No standard stdc++ libraries found.)
      ], []
)
CC="$oCC"
AC_SUBST(CXXLIBS)

# Does the compiler handle various std::foo namespaces properly?
oCC="$CC"
CC="$CXX"

AC_LINK_IFELSE([AC_LANG_PROGRAM([[
    #include <string>
    #include <cstdio>
]], [[
    char *foo;
    std::snprintf(foo, 10, "x");
    return 0;
]])],[],[AC_DEFINE(MISSING_STD_SNPRINTF, 1, we need to shim std snprintf)])

AC_LINK_IFELSE([AC_LANG_PROGRAM([[
    #include <string>
    #include <cstdio>
    #include <cmath>
]], [[
    std::isnan(1.0f);
    return 0;
]])],[],[AC_DEFINE(MISSING_STD_ISNAN, 1, we need to shim isnan)])

CC="$oCC"


AC_MSG_CHECKING([for group 'root'])
AS_IF([test "`grep -e ^root: /etc/group`" = ""],
      [
       AC_MSG_RESULT([no.  Using 'wheel'])
       instgrp="wheel"
      ],
      [
       AC_MSG_RESULT([yes])
       instgrp="root"
      ]
)
AC_SUBST(instgrp)

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
		    AC_LINK_IFELSE([AC_LANG_PROGRAM([[extern char *__progname, *__progname_full;]], [[__progname = "foo"; __progname_full = "foo bar";]])],[pf_cv_var_progname="yes"],[pf_cv_var_progname="no"]))

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
    AS_HELP_STRING([--disable-mutextimeout], [Disable failsafe thread mutex timer, use with caution]),
	[case "${enableval}" in
	  no) wantmutex=0 ;;
	   *) wantmutex=1 ;;
	 esac],
	[wantmutex=1]
)

if test "$wantmutex" = 0; then
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
    AS_HELP_STRING([--disable-linuxwext], [Disable Linux wireless extensions]),
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


# Look for capability support
AC_ARG_ENABLE(libcap,
    AS_HELP_STRING([--disable-libcap], [Disable libcap capabilities]),
	[case "${enableval}" in
	  no) wantlibcap=no ;;
	   *) wantlibcap=yes ;;
	 esac],
	[wantlibcap=yes]
)

if test "$wantlibcap" = "yes"; then
    havecap="yes"
    AC_CHECK_LIB([cap], [cap_init],,havecap=no)
    AC_CHECK_HEADER([sys/prctl.h],, havecap=no)
    AC_CHECK_HEADER([sys/capability.h],, havecap=no)

    if test "$havecap" = "yes"; then
    AC_DEFINE(HAVE_CAPABILITY, 1, kernel capability support)
    caplibs="-lcap"
    AC_SUBST(caplibs)
    fi
fi

fi # linux

AC_ARG_WITH(pcreheaders,
	[  --with-pcreheaders[=DIR]      Custom location of the PCRE library headers ],
	[
   	 if test "$withval" != no -a "$withval" != "yes"; then
        CPPFLAGS="$CPPFLAGS -I$withval"
    fi
	])

AC_ARG_ENABLE(pcre,
    AS_HELP_STRING([--disable-pcre], [Disable PCRE regex]),
	[case "${enableval}" in
	  no) wantpcre=no ;;
	   *) wantpcre=yes ;;
	 esac],
	[wantpcre=yes]
)

AC_ARG_ENABLE(require-pcre2,
    AS_HELP_STRING([--enable-require-pcre2], [Explicitly require libpcre2]),
	[case "${enableval}" in
	  yes) needpcre2=yes ;;
	    *) needpcre2=no ;;
	 esac],
	[needpcre2=no]
)

if test "${wantpcre}x" = "nox" -a "${needpcre2}x" = "yesx"; then
    AC_MSG_ERROR([Can not combine --disable-pcre and --enable-require-pcre2])
fi

if test "$caponly"x = "no"x; then
    if test "$HAVE_CXX17" = "1"; then
	    AC_MSG_CHECKING([Checking C++17 parallel functions])

	    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
                #include <execution>
                #include <vector>
	    		]], [[
                std::vector<int> x{1, 2};
                std::stable_sort(std::execution::par_unseq, x.begin(), x.end(), [&](int, int) -> bool { return false; });
	    		return 0;
	    		]])],
                [
                 AC_MSG_RESULT([ok])
                 USE_CPP17_PARALLEL=1
                 AC_DEFINE(HAVE_CPP17_PARALLEL, 1, CPP17 parallel functions work)
                ],[
                 AC_MSG_RESULT([fail])
                 AC_MSG_WARN([Could not use basic C++17 parallel functions])
                 USE_CPP17_PARALLEL=0
                ])

        if test "$USE_CPP17_PARALLEL" = "0"; then
            OCXLIBS="$CXXLIBS"
            CXXLIBS="$CXXLIBS -ltbb"

	        AC_MSG_CHECKING([Checking C++17 parallel functions with libtbb])
	        AC_LINK_IFELSE([AC_LANG_PROGRAM([[
                    #include <execution>
                    #include <vector>
	        		]], [[
                    std::vector<int> x{1, 2};
                    std::stable_sort(std::execution::par_unseq, x.begin(), x.end(), [&](int, int) -> bool { return false; });
	        		return 0;
	        		]])],
                    [
                     AC_MSG_RESULT([ok])
                     USE_CPP17_PARALLEL=1
                     AC_DEFINE(HAVE_CPP17_PARALLEL, 1, CPP17 parallel functions work)
                    ],[
                     AC_MSG_RESULT([fail])
                     AC_MSG_WARN([Could not use basic C++17 parallel functions with -ltbb])
                     USE_CPP17_PARALLEL=0
                     CXXLIBS="$OCXLIBS"
                    ])
        fi

        if test "$USE_CPP17_PARALLEL" = "0"; then
            OCXLIBS="$CXXLIBS"
            CXXLIBS="$CXXLIBS -ltbb2"

	        AC_MSG_CHECKING([Checking C++17 parallel functions with libtbb2])
	        AC_LINK_IFELSE([AC_LANG_PROGRAM([[
                    #include <execution>
                    #include <vector>
	        		]], [[
                    std::vector<int> x{1, 2};
                    std::stable_sort(std::execution::par_unseq, x.begin(), x.end(), [&](int, int) -> bool { return false; });
	        		return 0;
	        		]])],
                    [
                     AC_MSG_RESULT([ok])
                     USE_CPP17_PARALLEL=1
                     AC_DEFINE(HAVE_CPP17_PARALLEL, 1, CPP17 parallel functions work)
                    ],[
                     AC_MSG_RESULT([fail])
                     AC_MSG_WARN([Could not use basic C++17 parallel functions with -ltbb2])
                     USE_CPP17_PARALLEL=0
                     CXXLIBS="$OCXLIBS"
                    ])
        fi
    fi

    # Do we need libtbb for parallel threading?
    # AC_CHECK_LIB([tbb], [main], CXXLIBS="$CXXLIBS -ltbb")
fi

# Dont' check pcre if we're only building datasources
if test "$caponly"x = "no"x; then
    if test "$wantpcre" = "yes"; then
        # Check for pcre2 first

        pcre2=no
        pcre1=no

        OLIBS="$LIBS"
        LIBS="$LIBS -lpcre2-8"

	    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
            #define PCRE2_CODE_UNIT_WIDTH 8
            #include <pcre2.h>
			]], [[

            pcre2_compile(NULL, PCRE2_ZERO_TERMINATED,
                          0, NULL, NULL, NULL);

			return 0;
			]])],
            [
                pcre2=yes
            ],[
                pcre2=no
            ])

        LIBS="$OLIBS"

        if test "$pcre2" != "yes"; then
            if test "${needpcre2}x" = "yesx"; then
                AC_MSG_ERROR([Could not find libpcre2 and --enable-require-pcre2 selected])
            fi

    	    AC_CHECK_LIB([pcre], [pcre_compile], pcre1=yes, pcre1=no)

            if test "$pcre1" = "yes"; then
    	        AC_CHECK_HEADER([pcre.h], pcre1=yes, pcre1=no)
            fi

        fi

        if test "$pcre2" = "yes"; then
            AC_DEFINE(HAVE_LIBPCRE2, 1, libpcre2 regex support)
            LIBS="$LIBS -lpcre2-8"
        elif test "$pcre1" = "yes"; then
            AC_DEFINE(HAVE_LIBPCRE, 1, libpcre1 regex support)
            LIBS="$LIBS -lpcre"
        else
            AC_MSG_WARN([Failed to find libpcre or libpcre2 library and headers, make sure that pcre2-dev is installed])
        fi
    fi
fi

# Don't check for sqlite3 if we're only building datasources
if test "$caponly"x = "no"x; then
    # Check for sqlite3
    sql3l=no
    AC_CHECK_LIB([sqlite3], [sqlite3_libversion], sql3l=yes, sql3l=no)

    if test "$sql3l" != "yes"; then
    	AC_MSG_ERROR(Failed to find libsqlite3)
    fi


    sql3h=no
    AC_CHECK_HEADER([sqlite3.h], sql3h=yes, sql3h=no)

    if test "$sql3h" != "yes"; then
    	AC_MSG_ERROR(Failed to find sqlite3 headers check that the libsqlite3-devel package is installed if your distribution provides separate packages)
    fi

    if test "$sql3h" = "yes" -a "$sql3l" = "yes"; then
    AC_DEFINE(HAVE_LIBSQLITE3, 1, libsqlite3 database support)
    LIBS="$LIBS -lsqlite3"
    else
        AC_MSG_ERROR(Failed to find sqlite3)
    fi # sqlite3

fi # caponly

# don't check for openssl if we're only building datasources
if test "$caponly"x = "no"x; then
    AX_CHECK_OPENSSL(AC_DEFINE(HAVE_OPENSSL, 1, openssl library present),
                     AC_MSG_ERROR(Failed to find OpenSSL library))
fi # caponly

wantprelude=no
# AC_ARG_ENABLE(prelude,
#               AS_HELP_STRING([--enable-prelude],
#                              [Enable Prelude SIEM as a target for alerts.]),
# [
#   wantprelude=no
#   if test "$enableval" != "no"; then
#     AM_PATH_LIBPRELUDE(1.2.6, , AC_MSG_ERROR(Cannot find libprelude: Is libprelude-config in the path?), no)
#     CPPFLAGS="${CPPFLAGS} ${LIBPRELUDE_CFLAGS}"
#     LDFLAGS="${LDFLAGS} ${LIBPRELUDE_LDFLAGS}"
#     LIBS="${LIBS} ${LIBPRELUDE_LIBS}"
#     AC_DEFINE([PRELUDE], [1], [Libprelude support enabled])
#     wantprelude=yes
#   fi
# ],[wantprelude=no])


PKG_PROG_PKG_CONFIG

AC_ARG_ENABLE([libwebsockets],
    AS_HELP_STRING([--disable-libwebsockets], [Disable C-based libwebsockets, this will only impact building remote capture sources.  The Kismet server will still have websockets support.]),
	[case "${enableval}" in
	  no) want_libwebsockets=no ;;
	   *) want_libwebsockets=yes ;;
	 esac],
	[want_libwebsockets=yes]
)

AS_IF([test "x$want_libwebsockets" != "xno"], [
    PKG_CHECK_MODULES([libwebsockets], [libwebsockets >= 3.1.0], have_libwebsockets_pkg=yes)

    if test x"$have_libwebsockets_pkg" != "xyes"; then
        AC_MSG_ERROR([required libwebsockets not available, configure with --disable-websockets to turn off remote capture libwebsockets support.  This will only impact remote capture sources.])
    else
        AC_CHECK_LIB([websockets], [lws_client_connect_via_info],
                     [
                     LIBWSLIBS=`pkg-config --libs libwebsockets`
                     LIBWSFLAGS=`pkg-config --cflags libwebsockets`

                     have_libwebsockets="yes"
                     AC_DEFINE(HAVE_LIBWEBSOCKETS, 1, libwebsockets)
                     ],
                     AC_MSG_ERROR("libwebsockets not compiled with client support"))
    fi
])
AC_SUBST(LIBWSLIBS)
AC_SUBST(LIBWSCFLAGS)

# Look for libpcap via pkg-config
have_libpcap=no
PKG_CHECK_MODULES([libpcap], [libpcap], [
    have_libpcap=yes
    AC_DEFINE(HAVE_LIBPCAP, 1, libpcap packet capture lib)

    PCAPLIBS=`pkg-config --libs libpcap`
    PCAPCFLAGS=`pkg-config --cflags libpcap`
    pcap=yes
    ], [
    AC_MSG_WARN(No libpcap found in pkg-config, will check system paths.)
    ])

# Look for pcap using our legacy mode
if test "$have_libpcap"x != "yesx"; then
    AC_CHECK_LIB([pcap], [pcap_open_live],
        AC_DEFINE(HAVE_LIBPCAP, 1, libpcap packet capture lib) foundsyspcap=yes,
        AC_MSG_ERROR(Libpcap required for proper operation))

    if test "$foundsyspcap" = yes; then
    ## if we don't have a pcap.h, do a search for pcap/pcap.h
    AC_CHECK_HEADER([pcap.h],
    	AC_DEFINE(HAVE_PCAP_H, 1, libpcap header) foundsyspcaph=yes)
        if test "$foundsyspcaph" != yes; then
    		AC_CHECK_HEADER([pcap/pcap.h],
    		AC_DEFINE(HAVE_PCAP_H, 1, libpcap header) AC_DEFINE(HAVE_PCAPPCAP_H, 1, pcap/pcap.h),
    		AC_MSG_ERROR([found libpcap but unable to find pcap.h]))
        fi

        PCAPLIBS="-lpcap"
        PCAPCFLAGS=""
        pcap=yes
    fi
fi

AC_SUBST(PCAPLIBS)
AC_SUBST(PCAPCFLAGS)
AC_SUBST(pcap)

AS_IF([test "$pcap"x != "yes"x],
      [
       AC_MSG_ERROR(Could not find working libpcap.  Libpcap is vital for the majority of Kismet functionality.)
      ], []
)

DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_PCAPFILE)"
BUILD_CAPTURE_PCAPFILE=1

DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_ANTSDR_DRONEID)"
BUILD_CAPTUE_ANTSDR_DRONEID=1

BUILD_CAPTURE_LINUX_WIFI=0
AS_IF([test "$linux"x = "yes"x],
      [
       DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_LINUX_WIFI)"
       BUILD_CAPTURE_LINUX_WIFI=1
      ], []
)

BUILD_CAPTURE_OPENBSD_WIFI=0
if test "$openbsd" = "yes"; then
    DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_OPENBSD_WIFI)"
    BUILD_CAPTURE_OPENBSD_WIFI=1
fi

AS_IF([test "$want_protobuf"x = "yes"x], [
    PKG_CHECK_MODULES([protobuf], [${PROTOBUF}], have_protobuf_pkg=yes)
    if test x"$have_protobuf_pkg" != "xyes"; then
        AC_MSG_ERROR([missing google libprotobuf])
    fi

    AC_ARG_WITH(protoc,
    	[  --with-protoc[=PATH]     Custom location of the protoc protobuf compiler],
        [ ])

    if test x"$with_protoc" = "x"; then
        PROTOCBIN=protoc
        AC_CHECK_PROG(protoc, [protoc], yes)
        if test x"$protoc" != x"yes"; then
            AC_MSG_ERROR([missing google libprotobuf protoc compiler])
        fi
    else
        PROTOCBIN=$with_protoc
    fi

    PROTOLIBS=`pkg-config --libs ${PROTOBUF}`
    PROTOCFLAGS=`pkg-config --cflags ${PROTOBUF}`

    # Enable the C++ targets
    PROTOBUF_CPP_O_TARGET='$(PROTOBUF_CPP_O)'
    PROTOBUF_CPP_H_TARGET='$(PROTOBUF_CPP_H)'

    AC_DEFINE(HAVE_PROTOBUF_CPP, 1, google protobufs)
], [])

AC_SUBST(PROTOBUF_CPP_O_TARGET)
AC_SUBST(PROTOBUF_CPP_H_TARGET)
AC_SUBST(PROTOLIBS)
AC_SUBST(PROTOCFLAGS)
AC_SUBST(PROTOCBIN)

AC_ARG_ENABLE(btgeiger,
    AS_HELP_STRING([--enable-btgeiger], [Enable custom BTLE connected geiger counter input]),
    [case "${enableval}" in
      yes) want_btgeiger=yes ;;
        *) want_btgeiger=no ;;
    esac],
    [want_btgeiger=no]
)

AS_IF([test "x$want_btgeiger" = "xyes"], [
       AS_IF([test "x$want_python" != "xyes"], [
              AC_MSG_ERROR([Can not enable btgeiger without enabling python])
              ])
       BUILD_CAPTURE_BT_GEIGER=1
       DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_BT_GEIGER)"
])


# To use wiphy we need a very recent bladerf, and we need it even when only building for caponly
AC_ARG_ENABLE(bladerf,
    AS_HELP_STRING([--enable-bladerf], [Enable bladeRF2-wiphy support]),
    [case "${enableval}" in
      yes) want_bladerf=yes ;;
        *) want_bladerf=no ;;
    esac],
    [want_bladerf=no]
)

AS_IF([test "x$want_bladerf" = "xyes"], [
    PKG_CHECK_MODULES([libbladeRF], [libbladeRF],
        [
        ],
        [
         AC_MSG_ERROR([missing libbladeRF package])
        ])

    BLADERFLIBS=`pkg-config --libs libbladeRF`
    BLADERFCFLAGS=`pkg-config --cflags libbladeRF`

    OCFL="$CFLAGS"

    CFLAGS="$CFLAGS $BLADERFCFLAGS"

    AC_CHECK_LIB([bladeRF], [bladerf_open],
                 [
                  LIBBLADERF="-lbladerf2"
                  have_libbladerf="yes"
                  AC_DEFINE(HAVE_LIBBLADERF, 1, libbladerf)
                 ],
                 [
                  AC_MSG_ERROR([missing libbladerf2])
                 ])

	AC_MSG_CHECKING([Required libbladerf2 version])
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[
            #include <libbladeRF.h>
			]], [[
            #if LIBBLADERF_API_VERSION < 0x02020100
            #error Version too old
            #endif
			return 0;
			]])],
            [
             AC_MSG_RESULT([ok])
            ],[
             AC_MSG_RESULT([fail])
             AC_MSG_ERROR([libbladerf2 version too old, you likely need a git version of libbladerf2])
            ])

	AC_MSG_CHECKING([Required libbladerf2 packet modes])
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[
            #include <libbladeRF.h>
			]], [[
            int x = (int) BLADERF_FORMAT_PACKET_META;
			return 0;
			]])],
            [
             AC_MSG_RESULT([packet_meta])
            ],[
             AC_MSG_RESULT([fail])
             AC_MSG_ERROR([unable to find PACKET_META format, you likely need a git version of libbladerf2])
            ])

    CFLAGS="$OCFL"

    BUILD_CAPTURE_BLADERF_WLAN=1
])

AC_SUBST(BLADERFLIBS)
AC_SUBST(BLADERFCFLAGS)
AC_SUBST(BUILD_CAPTURE_BLADERF_WLAN)

if test x"$BUILD_CAPTURE_BLADERF_WLAN" = x"1"; then
    DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_BLADERF_WIPHY)"
fi

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
	AC_MSG_RESULT(Using local radiotap headers)
fi

if test "$radiotap" != "yes"; then
    AC_DEFINE(HAVE_LOCAL_RADIOTAP, 1, local radiotap packet headers)
	radiotaploc="local"
fi

if test "$bsdradiotap" = "yes"; then
	AC_DEFINE(HAVE_BSD_SYS_RADIOTAP, 1, BSD radiotap packet headers)
	radiotaploc="system (BSD)"
fi

if test "$linux" = "yes"; then

NMLIBS=""
NMCFLAGS=""

want_libnm="yes"
AC_ARG_ENABLE(libnm,
    AS_HELP_STRING([--disable-libnm], [Disable libnm networkmanager support]),
	[case "${enableval}" in
	  no) want_libnm=no ;;
	   *) want_libnm=yes ;;
	 esac],
	[want_libnm=yes]
    )

AS_IF([test "x$want_libnm" != "xno"], [

# Do we want to check it
PKG_CHECK_MODULES([libnm], [libnm], havelibnm=yes, havelibnm=no)
AS_IF([test "x$havelibnm" = "xyes"], [
    NMLIBS=`pkg-config --libs libnm`
    NMCFLAGS=`pkg-config --cflags libnm`
], [
    LIBNM_MISSING_REASON="libnm package not found"
])

# Did it pass pkg check?
AS_IF([test "x$havelibnm" = "xyes"], [
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
])

# Did it fail compile test?
AS_IF([test "x$havelibnm" != "xyes"], [
	AC_MSG_WARN(Libnm missing device_set_managed function may be a very old version)
	havelibnm=no
    NMLIBS=""
    NMCFLAGS=""
    LIBNM_MISSING_REASON="libnm missing required functions, may be very out of date"
])

# We're good
AS_IF([test "x$havelibnm" = "xyes"], [
    AC_DEFINE(HAVE_LIBNM, 1, NetworkManager interface library)
])

],
[
    LIBNM_MISSING_REASON="libnm disabled"
])


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
        if test "$picked_nl" = "tiny"; then
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

want_usb="yes"
have_usb="no"

AC_ARG_ENABLE([libusb],
    AS_HELP_STRING([--disable-libusb], [Disable libUSB support and any libUSB based data sources]),
	[case "${enableval}" in
	  no) want_usb=no ;;
	   *) want_usb=yes ;;
	 esac],
	[want_usb=yes]
)

AS_IF([test "x$want_usb" != "xno"], [
    PKG_CHECK_MODULES([libusb], [libusb-1.0], have_libusb_pkg=yes)

    if test x"$have_libusb_pkg" != "xyes"; then
        AC_MSG_ERROR([missing libusb-1.0])
    else
        LIBUSBLIBS=`pkg-config --libs libusb-1.0`
        LIBUSBCFLAGS=`pkg-config --cflags libusb-1.0`

        have_usb="yes"
    fi
])
AC_SUBST(LIBUSBLIBS)
AC_SUBST(LIBUSBCFLAGS)

want_coconut="no"
AC_ARG_ENABLE([wifi-coconut],
    AS_HELP_STRING([--enable-wifi-coconut], [Enable Hak5 WiFi Coconut userspace]),
	[case "${enableval}" in
         yes) want_coconut=yes ;;
           *) want_coconut=no ;;
	 esac],
         [want_coconut=no]
)

BUILD_CAPTURE_HAK5_COCONUT=0
if test x"$want_coconut" = x"yes"; then
    if test x"$have_usb" != "xyes"; then
        AC_MSG_ERROR([libusb-1.0 required for Hak5 WiFi Coconut support])
    fi
    BUILD_CAPTURE_HAK5_COCONUT=1
    DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_HAK5_COCONUT)"
fi


want_ubertooth="yes"
AC_ARG_ENABLE([ubertooth],
    AS_HELP_STRING([--disable-ubertooth], [Disable Ubertooth One support]),
	[case "${enableval}" in
	  no) want_ubertooth=no ;;
	   *) want_ubertooth=yes ;;
	 esac],
	[want_ubertooth=yes]
)

AS_IF([test "xwant_ubertooth" != "xno"], [
    OCFL="$CFLAGS"
    OCPPFL="$CPPFLAGS"
    OLFL="$LDFLAGS"

    CFLAGS="$CFLAGS $LIBUSBCFLAGS"
    CPPFLAGS="$CPPFLAGS $LIBUSBCFLAGS"
    LDFLAGS="$LDFLAGS $LIBUSBLIBS"

    CANT_BUILD_UBERTOOTH=0
    LIBUBERTOOTHLIBS=""
    LIBUBERTOOTHCFLAGS=""

    if test x"$have_usb" != "xyes"; then
        AC_MSG_WARN([missing libusb, ubertooth-one support will not be built])
        CANT_BUILD_UBERTOOTH=1
    else
        AC_CHECK_HEADERS([btbb.h],
                         HAVE_BTBB_H=yes,
                         AC_MSG_WARN("btbb.h is missing"))
        AC_CHECK_LIB([btbb], [btbb_init],
                     HAVE_LIBBTBB=yes,
                     AC_MSG_WARN("libbtbb is missing"))

        if test x"$HAVE_BTBB_H" != "xyes" -o x"$HAVE_LIBBTBB" != "xyes"; then
            AC_MSG_WARN([missing libbtbb, ubertooth-one support will not be built])
            CANT_BUILD_UBERTOOTH=1
        else
            LIBBTBBCFLAGS=""
            LIBBTBBLIBS="-lbtbb"
            LDFLAGS="$LDFLAGS -lbtbb"

            AC_CHECK_HEADERS([ubertooth/ubertooth.h],
                             [HAVE_UBERTOOTH_H=yes
                              AC_DEFINE(HAVE_UBERTOOTH_UBERTOOTH_H, 1, ubertooth.h in ubertooth dir)],
                              [])

            AC_CHECK_HEADERS([ubertooth.h],
                             HAVE_UBERTOOTH_H=yes, [])

            AC_CHECK_LIB([ubertooth], [ubertooth_init],
                         HAVE_LIBUBERTOOTH=yes, [])

            if test x"$HAVE_UBERTOOTH_H" != "xyes" -o x"$HAVE_LIBUBERTOOTH" != "xyes"; then
                AC_MSG_WARN([missing libubertooth, ubertooth-one support will not be built])
                CANT_BUILD_UBERTOOTH=1
            else
                LIBUBERTOOTHCFLAGS=""
                LIBUBERTOOTHLIBS="-lubertooth"
            fi
        fi
    fi

    if test $CANT_BUILD_UBERTOOTH = 1; then
        AC_MSG_WARN([missing one or more required libraries for ubertooth-one])
        have_ubertooth="no"
    else
        have_ubertooth="yes"

        AC_CHECK_LIB([ubertooth], [ubertooth_count],
                     AC_DEFINE(HAVE_LIBUBERTOOTH_UBERTOOTH_COUNT, 1, libubertooth has ubertooth_count),
                     HAVE_UBERTOOTH_COUNT=0)

    fi

    CFLAGS="$OCFL"
    CPPFLAGS="$OCPPFL"
    LDFLAGS="$OLFL"
])

AC_SUBST(LIBUBERTOOTHLIBS)
AC_SUBST(LIBUBERTOOTHCFLAGS)
AC_SUBST(LIBBTBBLIBS)
AC_SUBST(LIBBTBBCFLAGS)

BUILD_CAPTURE_UBERTOOTH_ONE=0
if test x"$have_ubertooth" = x"yes"; then
    BUILD_CAPTURE_UBERTOOTH_ONE=1
    DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_UBERTOOTH_ONE)"
fi

AC_ARG_ENABLE([librtlsdr],
    AS_HELP_STRING([--disable-librtlsdr], [Disable librtlsdr support and any librtlsdr based data sources]),
	[case "${enableval}" in
	  no) want_rtlsdr=no ;;
	   *) want_rtlsdr=yes ;;
	 esac],
	[want_rtlsdr=yes]
)

AS_IF([test "x$want_rtlsdr" != "xno"], [
    PKG_CHECK_MODULES([librtlsdr], [librtlsdr], have_librtlsdr_pkg=yes)

    if test x"$have_librtlsdr_pkg" != "xyes"; then
        AC_MSG_ERROR([missing librtlsdr])
    else
        LIBRTLLIBS=`pkg-config --libs librtlsdr`
        LIBRTLCFLAGS=`pkg-config --cflags librtlsdr`

        have_rtlsdr="yes"

        OLIBS="$LIBS"
        LIBS="$LIBS $LIBRTLLIBS"

        OCFL="$CFLAGS"
        CFLAGS="$CFLAGS $LIBRTLCFLAGS"

        rtlsdr_bias_tee=no
        rtlsdr_bias_tee_gpio=no

	    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
            #include <rtl-sdr.h>
			]], [[

            rtlsdr_set_bias_tee(nullptr, 1);

			return 0;
			]])],
            [
                rtlsdr_bias_tee=yes
            ],[
                rtlsdr_bias_tee=no
            ])

	    AC_LINK_IFELSE([AC_LANG_PROGRAM([[
            #include <rtl-sdr.h>
			]], [[

            rtlsdr_set_bias_tee_gpio(nullptr, 0, 1);

			return 0;
			]])],
            [
                rtlsdr_bias_tee_gpio=yes
            ],[
                rtlsdr_bias_tee_gpio=no
            ])


        LIBS="$OLIBS"
        CFLAGS="$OCFL"

        if test "$rtlsdr_bias_tee"x = "yes"x; then
            AC_DEFINE(HAVE_LIBRTLSDR_BIAS_T, 1, librtlsdr bias-tee support)
        fi

        if test "$rtlsdr_bias_tee_gpio"x = "yes"x; then
            AC_DEFINE(HAVE_LIBRTLSDR_BIAS_T_GPIO, 1, librtlsdr bias-tee-gpio support)
        fi
    fi
])
AC_SUBST(LIBRTLLIBS)
AC_SUBST(LIBRTLCFLAGS)

BUILD_CAPTURE_NRF_MOUSEJACK=0
if test "$have_usb" = "yes"; then
    BUILD_CAPTURE_NRF_MOUSEJACK=1
    DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_NRF_MOUSEJACK)"
fi

BUILD_CAPTURE_TI_CC_2540=0
if test "$have_usb" = "yes"; then
    BUILD_CAPTURE_TI_CC_2540=1
    DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_TI_CC_2540)"
fi

BUILD_CAPTURE_TI_CC_2531=0
if test "$have_usb" = "yes"; then
    BUILD_CAPTURE_TI_CC_2531=1
    DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_TI_CC_2531)"
fi

BUILD_CAPTURE_USB_RADIACODE=0
if test "$have_usb" = "yes"; then
    BUILD_CAPTURE_USB_RADIACODE=1
    DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_USB_RADIACODE)"
fi

BUILD_CAPTURE_SDR_RTL433V2=0
if test "$have_usb" = "yes" -a "$have_rtlsdr" = "yes"; then
    BUILD_CAPTURE_SDR_RTL433V2=1
    DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_SDR_RTL433V2)"
fi

BUILD_CAPTURE_SDR_RTLADSBV2=0
if test "$have_usb" = "yes" -a "$have_rtlsdr" = "yes"; then
    BUILD_CAPTURE_SDR_RTLADSBV2=1
    DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_SDR_RTLADSBV2)"
fi

BUILD_CAPTURE_LINUX_BLUETOOTH=0
if test "$linux" = "yes"; then
    BUILD_CAPTURE_LINUX_BLUETOOTH=1
    DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_LINUX_BLUETOOTH)"
fi

# All this depends on is serial so we build it all the time
BUILD_CAPTURE_SERIAL_RADVIEW=1
DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_SERIAL_RADVIEW)"

# All these depend on is serial, so we build them all the time
BUILD_CAPTURE_NRF_51822=1
DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_NRF_51822)"

BUILD_CAPTURE_NXP_KW41Z=1
DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_NXP_KW41Z)"

BUILD_CAPTURE_NRF_52840=1
DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_NRF_52840)"

BUILD_CAPTURE_FREAKLABS_ZIGBEEV2=1
DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_FREAKLABS_ZIGBEEV2)"

BUILD_CAPTURE_RZ_KILLERBEE=0
if test "$have_usb" = "yes"; then
    BUILD_CAPTURE_RZ_KILLERBEE=1
    DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_RZ_KILLERBEE)"
fi


if test "$darwin" = "yes"; then
	suidgroup="staff"
    BUILD_CAPTURE_OSX_COREWLAN=1
    DATASOURCE_BINS="$DATASOURCE_BINS \$(CAPTURE_OSX_COREWLAN)"
else
	suidgroup="kismet"
fi

want_mosquitto="yes"
AC_ARG_ENABLE(mosquitto,
    AS_HELP_STRING([--disable-mosquitto], [Disable MQTT support]),
	[case "${enableval}" in
	  no) want_mosquitto=no ;;
	   *) want_mosquitto=yes ;;
	 esac],
	[want_mosquitto=yes]
    )

AS_IF([test "x$want_mosquitto" != "xno"], [
    PKG_CHECK_MODULES([libmosquitto], [libmosquitto], have_libmosquitto_pkg=yes)

    if test x"$have_libmosquitto_pkg" != "xyes"; then
        AC_MSG_ERROR([required libmosquitto not available, configure with --disable-mosquitto to turn off MQTT support.])
    else
        AC_CHECK_LIB([mosquitto], [mosquitto_lib_init],
                     [
                      LIBS="$LIBS `pkg-config --libs libmosquitto`"
                      CPPFLAGS="$CPPFLAGS `pkg-config --cflags libmosquitto`"
                      CFLAGS="$CFLAGS `pkg-config --cflags libmosquitto`"

                      have_mosquitto="yes"
                      AC_DEFINE(HAVE_LIBMOSQUITTO, 1, libmosquitto)
                     ],
                     AC_MSG_ERROR([libmosquitto not available]))
    fi

],
[
    MQTT_MISSING_REASON="libmosquitto MQTT disabled"
])


AS_IF([test "$linux" = "yes"], [

want_lmsensors="yes"
AC_ARG_ENABLE(lmsensors,
    AS_HELP_STRING([--disable-lmsensors], [Disable lmsensors support]),
	[case "${enableval}" in
	  no) want_lmsensors=no ;;
	   *) want_lmsensors=yes ;;
	 esac],
	[want_lmsensors=yes]
    )

AS_IF([test "x$want_lmsensors" != "xno"], [
    AC_CHECK_HEADERS([sensors/sensors.h],
        HAVE_LMSENSORS_H=1,
        HAVE_LMSENSORS_H=0)

    if test "$HAVE_LMSENSORS_H" = 1; then
        AC_CHECK_LIB([sensors], [sensors_init],
    			HAVE_LIBLMSENSORS=1,
                HAVE_LIBLMSENSORS=0)

        if test "$HAVE_LIBLMSENSORS" = 1; then
            LIBS="$LIBS -lsensors"
            have_lmsensors=yes
        else
            AC_MSG_ERROR([required libsensors lm-sensors missing, configure with --disable-lmsensors to compile without thermal information])
        fi
    else
        AC_MSG_ERROR([required libsensors lm-sensors missing, configure with --disable-lmsensors to compile without thermal information])
    fi
],
[
    LMSENSORS_MISSING_REASON="lmsensors disabled"
])
])

AC_ARG_WITH(suidgroup,
	[  --with-suidgroup=group       Group allowed to execute the kismet_capture suid root helper process ],
	[
   	 if test "$withval"x != "x"; then
	 	suidgroup="$withval"
     fi
	])
AC_SUBST(suidgroup)

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
if test "$want_asan" = "yes"; then
    CPPFLAGS="$CPPFLAGS -fsanitize=address -fno-omit-frame-pointer"
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
if test "$want_tsan" = "yes"; then
    CPPFLAGS="$CPPFLAGS -fsanitize=thread -fno-omit-frame-pointer"
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

AC_SUBST(DATASOURCE_BINS)
AC_SUBST(BUILD_CAPTURE_PCAPFILE)
AC_SUBST(BUILD_CAPTURE_KISMETDB)
AC_SUBST(BUILD_CAPTURE_LINUX_WIFI)
AC_SUBST(BUILD_CAPTURE_HACKRF_SWEEP)
AC_SUBST(BUILD_CAPTURE_LINUX_BLUETOOTH)
AC_SUBST(BUILD_CAPTURE_OPENBSD_WIFI)
AC_SUBST(BUILD_CAPTURE_OSX_COREWLAN)
AC_SUBST(BUILD_CAPTURE_SDR_RTL433)
AC_SUBST(BUILD_CAPTURE_SDR_RTLAMR)
AC_SUBST(BUILD_CAPTURE_SDR_RTLADSB)
AC_SUBST(BUILD_CAPTURE_BT_GEIGER)
AC_SUBST(BUILD_CAPTURE_SDR_RTL433V2)
AC_SUBST(BUILD_CAPTURE_SDR_RTLADSBV2)
AC_SUBST(BUILD_CAPTURE_FREAKLABS_ZIGBEEV2)
AC_SUBST(BUILD_CAPTURE_NRF_MOUSEJACK)
AC_SUBST(BUILD_CAPTURE_TI_CC_2540)
AC_SUBST(BUILD_CAPTURE_TI_CC_2531)
AC_SUBST(BUILD_CAPTURE_UBERTOOTH_ONE)
AC_SUBST(BUILD_CAPTURE_NRF_51822)
AC_SUBST(BUILD_CAPTURE_NXP_KW41Z)
AC_SUBST(BUILD_CAPTURE_PROXY_ADSB)
AC_SUBST(BUILD_CAPTURE_RZ_KILLERBEE)
AC_SUBST(BUILD_CAPTURE_NRF_52840)
AC_SUBST(BUILD_CAPTURE_HAK5_COCONUT)
AC_SUBST(BUILD_CAPTURE_SERIAL_RADVIEW)
AC_SUBST(BUILD_CAPTURE_USB_RADIACODE)
AC_SUBST(BUILD_CAPTURE_ANTSDR_DRONEID)

#AC_SUBST(CPPFLAGS)
#AC_SUBST(CFLAGS)
#AC_SUBST(CXXFLAGS)

AC_CONFIG_FILES([
    Makefile
    Makefile.inc
    packaging/kismet.pc
    packaging/systemd/kismet.service
    packaging/systemd/debug/kismet-debug.service
    capture_linux_bluetooth/Makefile
    capture_linux_wifi/Makefile
    capture_openbsd_wifi/Makefile
    capture_osx_corewlan_wifi/Makefile
    capture_nrf_mousejack/Makefile
    capture_sdr_rtl433_v2/Makefile
    capture_sdr_rtladsb_v2/Makefile
    capture_freaklabs_zigbee_v2/Makefile
    capture_ti_cc_2540/Makefile
    capture_ti_cc_2531/Makefile
    capture_ubertooth_one/Makefile
    capture_nrf_51822/Makefile
    capture_nxp_kw41z/Makefile
    capture_rz_killerbee/Makefile
    capture_bladerf_wiphy/Makefile
    capture_proxy_adsb/Makefile
    capture_nrf_52840/Makefile
    capture_hak5_wifi_coconut/Makefile
	capture_serial_radview/Makefile
	capture_radiacode/Makefile
    capture_antsdr_droneid/Makefile
    ])
AC_OUTPUT

echo
echo "Configuration complete: "
echo "         Compiling for: $host_os ($host_cpu)"
echo "           C++ Library: $foundcxxl"
printf "      Protobuf Library: "
if test "$want_protobuf"x = "yes"x; then
    echo "$PROTOBUF"
else
    echo "disabled"
fi
echo "   Installing as group: $instgrp"
echo "       Installing into: $prefix"
printf "          Setuid group: $suidgroup"

printf "        Prelude  SIEM : $wantprelude\n"

printf "            PCRE regex: "
if test "$pcre1" = "yes"; then
    echo "libpcre1"
elif test "$pcre2" = "yes"; then
    echo "libpcre2"
else
	echo "no"
fi

printf " Websocket datasources: "
if test "$have_libwebsockets"x = "yesx"; then
    echo "yes"
else
    echo "no (not building remote capture with websockets)"
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

printf "  Linux Wi-Fi capture : "
if test "$linux_wireless" = "yes"; then
	echo "yes"
elif test "$linux" != "yes"; then
	echo "n/a (only Linux)"
else
	echo "no"
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
    echo "no (will not be able to control NetworkManager, $LIBNM_MISSING_REASON)"
fi

# printf "        Mosquitto MQTT: "
# if test "$have_mosquitto" = "yes"; then
# 	echo "yes (libmosquitto MQTT support)";
# else
#     echo "no (will not support MQTT data sources, $MQTT_MISSING_REASON)"
# fi

printf "   Linux HCI Bluetooth: "
if test "$BUILD_CAPTURE_LINUX_BLUETOOTH" = 1; then
	echo "yes";
elif test "$linux" != "yes"; then
	echo "n/a (only Linux)"
else
	echo "no (will not be able to track Bluetooth on Linux)";
fi

printf " OpenBSD Wi-Fi capture: "
if test "$openbsd" = "yes"; then
	echo "yes"
elif test "$openbsd" != "yes"; then
	echo "n/a (only OpenBSD)"
else
	echo "no"
 fi

printf "   OSX/Darwin capture : "
if test "$darwin" = "yes"; then
	echo "yes"
elif test "$darwin" != "yes"; then
	echo "n/a (only OSX/Darwin)"
else
	echo "no"
fi

printf "         nRF MouseJack: "
if test "$BUILD_CAPTURE_NRF_MOUSEJACK" = 1; then
	echo "yes";
else
	echo "no (libusb-1.0 not available)";
fi

printf "       TI CC 2540 BTLE: "
if test "$BUILD_CAPTURE_TI_CC_2540" = 1; then
        echo "yes";
else
        echo "no (libusb-1.0 not available)";
fi

printf "     TI CC 2531 Zigbee: "
if test "$BUILD_CAPTURE_TI_CC_2531" = 1; then
	echo "yes";
else
	echo "no (libusb-1.0 not available)";
fi

printf "         Ubertooth One: "
if test "$BUILD_CAPTURE_UBERTOOTH_ONE" = 1; then
        echo "yes";
else
        echo "no (libubertooth, libbtbb, or libusb-1.0 not available)";
fi

printf "         NRF51822 BTLE: "
if test "$BUILD_CAPTURE_NRF_51822" = 1; then
        echo "yes";
fi

printf "       NRF52840 Zigbee: "
if test "$BUILD_CAPTURE_NRF_52840" = 1; then
        echo "yes";
fi

printf "  NXP KW41Z BLE/Zigbee: "
if test "$BUILD_CAPTURE_NXP_KW41Z" = 1; then
        echo "yes";
else
        echo "no";
fi

printf "   Freaklabs Zigbee V2: "
if test "$BUILD_CAPTURE_FREAKLABS_ZIGBEEV2" = 1; then
        echo "yes";
else
        echo "no";
fi

printf "          RZ KILLERBEE: "
if test "$BUILD_CAPTURE_RZ_KILLERBEE" = 1; then
        echo "yes";
else
        echo "no (libusb-1.0 not available)";
fi

printf "        RADVIEW Serial: "
if test "$BUILD_CAPTURE_SERIAL_RADVIEW" = 1; then
        echo "yes";
else
        echo "no";
fi

printf "         Radiacode USB: "
if test "$BUILD_CAPTURE_USB_RADIACODE" = 1; then
        echo "yes";
else
        echo "no (libUSB not available)";
fi

printf "        Python Modules: "
	echo "no (deprecated)";

printf "    RTL-SDR RTL_433 V2: "
if test "$BUILD_CAPTURE_SDR_RTL433V2" = 1; then
	echo "yes";
else
    if test "$have_usb" != "yes"; then
	    echo "no (libusb not available)";
    elif test "$have_rtlsdr" != "yes"; then
        echo "no (librtlsdr not available)";
    else
        echo "no (not available)";
    fi
fi

printf "       RTL-SDR ADSB V2: "
if test "$BUILD_CAPTURE_SDR_RTLADSBV2" = 1; then
	echo "yes";
else
    if test "$have_usb" != "yes"; then
	    echo "no (libusb not available)";
    elif test "$have_rtlsdr" != "yes"; then
        echo "no (librtlsdr not available)";
    else
        echo "no (not available)";
    fi
fi

printf "        ANTSDR DroneID: "
if test "$BUILD_CAPTURE_ANTSDR_DRONEID" = 1; then
	echo "yes";
else
	echo "no";
fi

printf "         bladeRF-wiphy: "
if test "$BUILD_CAPTURE_BLADERF_WLAN" = 1; then
	echo "yes";
else
	echo "no (bladeRF support not explicitly enabled)";
fi

printf "     Hak5 WiFi Coconut: "
if test "$BUILD_CAPTURE_HAK5_COCONUT" = 1; then
	echo "yes";
else
	echo "no (Hak5 WiFi Coconut not explicitly enabled)";
fi

printf " lm-sensors monitoring: "
if test "x$have_lmsensors" = "xyes"; then
	echo "yes";
elif test "$linux" != "yes"; then
    echo "n/a (only Linux)"
else
	echo "no (will not be able to monitor system temperature, etc)";
fi

# printf "       HackRF spectrum: "
# if test "$BUILD_CAPTURE_HACKRF_SWEEP" -eq 1; then
# 	echo "yes (libhackrf and libfftw3 present)";
# else
# 	echo "no ($HACKRF_MISSING_REASON)";
# fi

printf "        Built-in Debug: "
echo $BACKTRACE_WARNING

if test "$havepkgconfig" = "no"; then
	echo
	echo "pkg-config was missing.  Without it, configure cannot detect "
	echo "several libraries Kismet needs.  Install pkg-config and re-run"
	echo "configure."
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

if test "$havenetlink" != "yes" -a "$linux" = "yes"; then
	echo
	echo "*** WARNING ***"
	echo "LibNL/nl80211 support was not found (or was disabled).  Kismet uses libnl to control "
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
    echo "libnm (the NetworkManager control library) was not found (or it was disabled). "
    echo "Kismet uses libnm to prevent NetworkManager from reconfiguring monitor mode "
    echo "interfaces while Kismet is running; without this library you will need to manually "
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


