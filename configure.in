# Process this file with autoconf to produce a configure script.
AC_INIT

m4_include([m4/ax_pthread.m4])

AC_CONFIG_SRCDIR([kismet.h])

AC_PREREQ(2.57)

# Check for host type
AC_CANONICAL_HOST

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_CPP

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
    hpux*)
        #
        # HP's ANSI C compiler; flags suggested by Jost Martin.
        # "-Ae" for ANSI C plus extensions such as "long long".
        # "+O2", for optimization.  XXX - works with "-g"?
        #
        CFLAGS="-Ae +O2 $CFLAGS"
        AC_MSG_RESULT(HP ANSI C compiler - added -Ae +O2)
        ;;
	darwin10*)
		# Snow leopard and newer, no -bundle in plugins
        CFLAGS="-no-cpp-precomp $CFLAGS"
		LDFLAGS="$LDFLAGS -framework Foundation -framework CoreFoundation -F/System/Library/PrivateFrameworks -framework Apple80211 -framework IOKit"
		PLUGINLDFLAGS="-flat_namespace -undefined suppress"
		objc_link='$(OBJC_CONTROL_O)'
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
		objc_link='$(OBJC_CONTROL_O)'
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
    solaris*)
        # the X11 headers don't automatically include prototype info
        # and a lot don't include the return type
        CFLAGS="$CFLAGS -Wno-return-type -DFUNCPROTO=15"
        AC_MSG_RESULT(GCC on Solaris - added -Wno-return-type -DFUNCPROTO=15)
        ;;
	darwin10*)
		# Snow leopard and newer, no -bundle in plugins
        CFLAGS="-no-cpp-precomp $CFLAGS"
		LDFLAGS="$LDFLAGS -framework Foundation -framework CoreFoundation -F/System/Library/PrivateFrameworks -framework Apple80211 -framework IOKit"
		PLUGINLDFLAGS="-flat_namespace -undefined suppress"
		objc_link='$(OBJC_CONTROL_O)'
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
		objc_link='$(OBJC_CONTROL_O)'
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

# Substitute in the objc linkages if we need them
AC_SUBST(PLUGINLDFLAGS)
AC_SUBST(objc_link)

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

# We need threads
AX_PTHREAD(pthread=1,
		   AC_MSG_ERROR([pthreads are needed and are not available]))
KSLIBS="$KSLIBS $PTHREAD_LIBS"
CPPFLAGS="$CPPFLAGS $PTHREAD_CFLAGS"

if test "$usedl" -eq 1; then
	LIBS="$LIBS -ldl"
	CLIENTCLIBS="$CLIENTCLIBS -ldl"
fi

# sqlite3=yes
# AC_CHECK_HEADER([sqlite3.h],
# 	AC_DEFINE(HAVE_SQLITE_H, 1, sqlite3.h is present) sqlite3=yes,
# 	sqlite3=no)
# 
# if test "$sqlite3" = yes; then
# AC_CHECK_LIB([sqlite3], [sqlite3_open], 
# 			 KSLIBS="$KSLIBS -lsqlite3", sqlite3=no)
# fi
# 
# if test "$sqlite3" != yes; then
# 	AC_MSG_WARN(Failed to find sqlite3 runtime resuming will be disabled)
# fi

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

if test "$foundcxxl"x == "x"; then
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

# Check for libcurses or libncurses.  Fatal error if we didn't use disable.
AC_ARG_ENABLE(client,
	[  --disable-client        disable kismet client],
	[case "${enableval}" in
	  no) wantclient=no ;;
	   *) wantclient=yes ;;
	 esac],
	[wantclient=yes]
)
AC_SUBST(wantclient)

# Add additional cflags since some distros bury panel.h
CPPFLAGS="$CPPFLAGS -I/usr/include/ncurses"

termcontrol="none";

if test "$wantclient" = "yes"; then
    OLIBS="$LIBS"
	AC_CHECK_LIB([ncurses], [initscr], 
		AC_DEFINE(HAVE_LIBNCURSES, 1, NCurses terminal lib) \
			foundlcurses=yes curseaux="-lncurses" termcontrol="ncurses" )

	if test "$foundlcurses" != "yes"; then
		AC_CHECK_LIB([curses], [initscr],
			 AC_DEFINE(HAVE_LIBCURSES, 1, Curses terminal lib) \
				 foundlcurses=yes curseaux="-lcurses" termcontrol="curses" )
	fi

	if test "$foundlcurses" != "yes"; then
		AC_MSG_ERROR(Failed to find libcurses or libncurses.  Install them or disable building the Kismet client with --disable-client.  Disabling the client is probably not something you want to do normally.)
	fi

	if test "$termcontrol" = "ncurses"; then
		AC_CHECK_HEADER([ncurses.h], [foundhcurses=yes])
	else
		AC_CHECK_HEADER([curses.h], [foundhcurses=yes])
	fi

	if test "$foundhcurses" != "yes"; then
		AC_MSG_ERROR(Failed to find curses.h or ncurses.h.  You probably need to install the curses-devel package from your distribution)
	fi

	LIBS="$LIBS $curseaux"
	AC_CHECK_LIB([panel], [new_panel],
				 AC_DEFINE(HAVE_LIBPANEL, 1, Panel terminal lib) 
				 curseaux="$curseaux -lpanel",
				 AC_MSG_ERROR(Failed to find libpanel extension to curses/ncurses.  Install it, or disable building the Kismet client with --disable-client.  Disabling the client is probably not something you want to do normally.))

	AC_CHECK_HEADER([panel.h], [foundhpanel=yes])
	if test "$foundhpanel" != "yes"; then
		AC_MSG_ERROR(Failed to find panel.h curses extension header.  You probably need to install the curses-devel or panel-devel package from your distribution.)
	fi

	LIBS="$OLIBS"

	CLIENTCLIBS="$CLIENTCLIBS $curseaux"
fi

AC_SUBST(CLIBS)
AC_SUBST(CLIENTCLIBS)
AC_SUBST(CLIENTCFLAGS)

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

# Look for libgps
# havelgps="yes"
# AC_CHECK_LIB([gps], [gps_open],,havelgps=no)
# AC_CHECK_HEADER([gps.h],,havelgps=no)
# 
# if test "$havelgps" = "yes"; then
# AC_DEFINE(HAVE_LIBGPS, 1, gpsd libgps client support)
# KSLIBS="$KSLIBS -lgps"
# fi

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
	fi
fi

if test "$wantpcap" = "yes" -a "$pcap" != "yes"; then
	AC_MSG_ERROR(Could not find working libpcap.  Libpcap is vital for the majority of capture sources Kismet supports.  It must be explicitly disabled.)
fi

if test "$wantpcap" != "yes" -o "$pcap" != "yes"; then
    AC_MSG_WARN(Compiling without libpcap support.  Many capture sources will be disabled.)
fi
AC_SUBST(pcap)

if test "$pcap" = "no" -a "$want_airpcap" = "yes"; then
	AC_MSG_WARN([*** Disabling AirPcap, libpcap not enabled ***]);
	want_airpcap=no;
fi

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
		KSLIBS="$KSLIBS -lairpcap"
	fi
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
# havenetlink=yes
# 	AC_CHECK_HEADERS([asm/types.h netlink/genl/genl.h netlink/genl/family.h netlink/genl/ctrl.h netlink/msg.h netlink/attr.h linux/nl80211.h linux/if_arp.h linux/wireless.h], 
# 	AC_DEFINE(HAVE_NETLINKHEADERS, 1, Netlink headers are there), 
# 	havenetlink=no,
# 	[#include <sys/socket.h>])
havenetlink=yes

#if test "$havenetlink" = "yes"; then
#	AC_CHECK_LIB([nl], [nl_handle_alloc],
#    AC_DEFINE(HAVE_LIBNL, 1, libnl netlink library), havenetlink=no)
#else
#	AC_MSG_WARN(Missing libnl or libnl too old support will not be able to control mac80211 vaps)
#fi

netlink_force=no

AC_ARG_WITH(netlink-version,
	[  --with-netlink-version[=1|2|3]     Force using libnl1, libnl2, or libnl-3 ],
	[
	netlink_force=$withval
	])

AC_CHECK_PROG(havepkgconfig, [pkg-config], yes, no)
if test "$havepkgconfig" = "no"; then
  AC_MSG_WARN(Missing pkg-config will lead to multiple other checks failing)
fi

NLLIBS=""
NLCFLAGS=""
nlname=""

if test "$havenetlink" = "yes"; then
	PKG_CHECK_MODULES(libnl30, [libnl-3.0], libnl30=yes, libnl30=no)
	PKG_CHECK_MODULES(libnlgenl30, [libnl-genl-3.0], libnlgenl30=yes, libnlgenl30=no)
	PKG_CHECK_MODULES(libnl20, [libnl-2.0], libnl20=yes, libnl20=no)
	PKG_CHECK_MODULES(libnl1, [libnl-1], libnl1=yes, libnl1=no)

	picked_nl=no
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
			nlname="libnl-1"
		fi
	fi

	if test $picked_nl = "no"; then
		havenetlink="no"
	fi

	if test "$nlname" != ""; then
		NLLIBS=`pkg-config --libs $nlname`
		NLCFLAGS=`pkg-config --cflags $nlname`
	fi
fi

if test "$havenetlink" = "yes"; then
	OLIBS="$LIBS"
	LIBS="$LIBS $NLLIBS"
	OCFL="$CPPFLAGS"
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
			]])],[havenetlink=yes KSLIBS="$KSLIBS $NLLIBS"],[havenetlink=no])
	
	LIBS="$OLIBS"
else
	AC_MSG_WARN(Missing libnl netlink library will not be able to control mac80211 vaps)
	havenetlink=no
fi

if test "$havenetlink" = "yes"; then
	AC_MSG_RESULT(yes)
	AC_DEFINE(HAVE_LINUX_NETLINK, 1, Netlink works) 
fi

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

    
# gpsmap checks

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

AC_SUBST(threadlib)

AC_SUBST(KSLIBS)

sharedatadir=$datadir
sharedatadir=`(
    test "$prefix" = NONE && prefix=$ac_default_prefix
    test "$exec_prefix" = NONE && exec_prefix=${prefix}
    eval echo "$sharedatadir"
)`
sharedatadir=${sharedatadir}
AC_SUBST(sharedatadir)

AC_CONFIG_FILES([Makefile Makefile.inc scripts/kismet conf/kismet.conf])
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


# printf "           GPSD LibGPS: "
# if test "$havelgps" = "yes"; then
# 	echo "yes (GPSD LibGPS client)";
# else
# 	echo "no (Using Kismet GPSD interface for GPSD <= 2.90)";
# fi

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
	echo "Run 'gmake dep' to generate dependencies and 'gmake' followed by"
	echo "'gmake install' to compile and install Kismet"
else
	verminor=`uname -r | cut -d '.' -f 2`
	# Stupid redhat
	vertiny=`uname -r | cut -d '.' -f 3 | cut -f 1 -d-`

	echo
	echo "Configuration complete.  Run 'make dep' to generate dependencies"
	echo "and 'make' followed by 'make install' to compile and install."
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

if test "$havenetlink" = "yes" -a "$pcap" = "yes"; then
	echo
	echo "*** WARNING ***"
	echo "In some situations, libpcap links to libnl.  If Kismet finds a newer "
	echo "libbl, it can cause an immediate segfault when starting Kismet. "
	echo
	echo "It is very hard to test at compile time (and run-time changes can "
	echo "cause it to break).  If you experience immediate segfaults when "
	echo "trying to start kismet_server, check your libpcap.so with 'ldd'"
	echo "and either install a libpcap which does not link libnl1, or "
	echo "force Kismet to compile with a degraded libnl via "
	echo "./configure --with-netlink-version=1"
	echo
fi


