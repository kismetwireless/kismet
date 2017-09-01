dnl Autoconf macros for libprelude
dnl $id$

# Modified for LIBPRELUDE -- Yoann Vandoorselaere
# Modified for LIBGNUTLS -- nmav
# Configure paths for LIBGCRYPT
# Shamelessly stolen from the one of XDELTA by Owen Taylor
# Werner Koch   99-12-09

dnl AM_PATH_LIBPRELUDE([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]], THREAD_SUPPORT)
dnl Test for libprelude, and define LIBPRELUDE_PREFIX, LIBPRELUDE_CFLAGS, LIBPRELUDE_PTHREAD_CFLAGS,
dnl LIBPRELUDE_LDFLAGS, and LIBPRELUDE_LIBS
dnl
AC_DEFUN([AM_PATH_LIBPRELUDE],
[dnl
dnl Get the cflags and libraries from the libprelude-config script
dnl
AC_ARG_WITH(libprelude-prefix, AC_HELP_STRING(--with-libprelude-prefix=PFX,
            Prefix where libprelude is installed (optional)),
            libprelude_config_prefix="$withval", libprelude_config_prefix="")

  if test x$libprelude_config_prefix != x ; then
     if test x${LIBPRELUDE_CONFIG+set} != xset ; then
        LIBPRELUDE_CONFIG=$libprelude_config_prefix/bin/libprelude-config
     fi
  fi

  AC_PATH_PROG(LIBPRELUDE_CONFIG, libprelude-config, no)
  if test "$LIBPRELUDE_CONFIG" != "no"; then
	if $($LIBPRELUDE_CONFIG --thread > /dev/null 2>&1); then
		LIBPRELUDE_PTHREAD_CFLAGS=`$LIBPRELUDE_CONFIG --thread --cflags`

		if test x$4 = xtrue || test x$4 = xyes; then
			libprelude_config_args="--thread"
		else
			libprelude_config_args="--no-thread"
		fi
	else
		LIBPRELUDE_PTHREAD_CFLAGS=`$LIBPRELUDE_CONFIG --pthread-cflags`
	fi
  fi

  min_libprelude_version=ifelse([$1], ,0.1.0,$1)
  AC_MSG_CHECKING(for libprelude - version >= $min_libprelude_version)
  no_libprelude=""
  if test "$LIBPRELUDE_CONFIG" = "no" ; then
    no_libprelude=yes
  else
    LIBPRELUDE_CFLAGS=`$LIBPRELUDE_CONFIG $libprelude_config_args --cflags`
    LIBPRELUDE_LDFLAGS=`$LIBPRELUDE_CONFIG $libprelude_config_args --ldflags`
    LIBPRELUDE_LIBS=`$LIBPRELUDE_CONFIG $libprelude_config_args --libs --c++`
    LIBPRELUDE_PREFIX=`$LIBPRELUDE_CONFIG $libprelude_config_args --prefix`
    LIBPRELUDE_CONFIG_PREFIX=`$LIBPRELUDE_CONFIG $libprelude_config_args --config-prefix`
    libprelude_config_version=`$LIBPRELUDE_CONFIG $libprelude_config_args --version`


      ac_save_CPPFLAGS="$CPPFLAGS"
      ac_save_LDFLAGS="$LDFLAGS"
      ac_save_LIBS="$LIBS"
      CPPFLAGS="$CPPFLAGS $LIBPRELUDE_CFLAGS"
      LDFLAGS="$LDFLAGS $LIBPRELUDE_LDFLAGS"
      LIBS="$LIBS $LIBPRELUDE_LIBS"
dnl
dnl Now check if the installed libprelude is sufficiently new. Also sanity
dnl checks the results of libprelude-config to some extent
dnl
      rm -f conf.libpreludetest
  AC_REQUIRE([AC_LANG_CPLUSPLUS])
  AC_REQUIRE([AC_PROG_CXX])
      AC_TRY_RUN([
#include <iostream>
#include <string>
#include <libprelude/prelude.hxx>
#include <cstdlib>

using namespace std;
using namespace Prelude;

int main ()
{
  system ("touch conf.libpreludetest");
  string cur_version(checkVersion(NULL));

	if ( cur_version.compare("$libprelude_config_version") )
	{
	cout <<"\n*** 'libprelude-config --version' returned " << "$libprelude_config_version" << ", but LIBPRELUDE (checkVersion(NULL))\n"  << endl ;
	cout <<"*** was found! If libprelude-config was correct, then it is best\n"  << endl ;
	cout <<"*** to remove the old version of LIBPRELUDE. You may also be able to fix the error\n"  << endl ;
	cout <<"*** by modifying your LD_LIBRARY_PATH enviroment variable, or by editing\n"  << endl ;
	cout <<"*** /etc/ld.so.conf. Make sure you have run ldconfig if that is\n"  << endl ;
	cout <<"*** required on your system.\n"  << endl ;
	cout <<"*** If libprelude-config was wrong, set the environment variable LIBPRELUDE_CONFIG\n"  << endl ;
	cout <<"*** to point to the correct copy of libprelude-config, and remove the file config.cache\n"  << endl ;
	cout <<"*** before re-running configure\n"  << endl ;
	}
	else if( cur_version.compare(LIBPRELUDE_VERSION) ){
		cout <<"\n*** LIBPRELUDE header file (version" << LIBPRELUDE_VERSION << ") does not match\n"  << endl ;
		cout <<"*** library (version" << checkVersion(NULL) << ")\n" << endl ;
	}
	else{
		if ( checkVersion( "$min_libprelude_version" ) ) return 0;
		else {
			cout <<"no\n*** An old version of LIBPRELUDE (" << "checkVersion(NULL)" << ") was found.\n"  << endl ;
			cout <<"*** You need a version of LIBPRELUDE newer than "<< "$min_libprelude_version" << ". The latest version of\n"  << endl ;
			cout <<"*** LIBPRELUDE is always available from http://www.prelude-ids.com/development/download/\n"  << endl ;
			cout <<"\n"  << endl ;
			cout <<"*** If you have already installed a sufficiently new version, this error\n"  << endl ;
			cout <<"*** probably means that the wrong copy of the libprelude-config shell script is\n"  << endl ;
			cout <<"*** being found. The easiest way to fix this is to remove the old version\n"  << endl ;
			cout <<"*** of LIBPRELUDE, but you can also set the LIBPRELUDE_CONFIG environment to point to the\n"  << endl ;
			cout <<"*** correct copy of libprelude-config. (In this case, you will have to\n"  << endl ;
			cout <<"*** modify your LD_LIBRARY_PATH enviroment variable, or edit /etc/ld.so.conf\n"  << endl ;
			cout <<"*** so that the correct libraries are found at run-time))\n"  << endl ;
		}
	}
	return 1;
}
],, no_libprelude=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
       CFLAGS="$ac_save_CFLAGS"
       LIBS="$ac_save_LIBS"
       LDFLAGS="$ac_save_LDFLAGS"
  fi

  if test "x$no_libprelude" = x ; then
     AC_MSG_RESULT(yes)
     ifelse([$2], , :, [$2])
  else
     if test -f conf.libpreludetest ; then
        :
     else
        AC_MSG_RESULT(no)
     fi
     if test "$LIBPRELUDE_CONFIG" = "no" ; then
       echo "*** The libprelude-config script installed by LIBPRELUDE could not be found"
       echo "*** If LIBPRELUDE was installed in PREFIX, make sure PREFIX/bin is in"
       echo "*** your path, or set the LIBPRELUDE_CONFIG environment variable to the"
       echo "*** full path to libprelude-config."
     else
       if test -f conf.libpreludetest ; then
        :
       else
          echo "*** Could not run libprelude test program, checking why..."
          CFLAGS="$CFLAGS $LIBPRELUDE_CFLAGS"
          LDFLAGS="$LDFLAGS $LIBPRELUDE_LDFLAGS"
          LIBS="$LIBS $LIBPRELUDE_LIBS"
          AC_TRY_LINK([
#include <string>
#include <iostream>
#include <libprelude/prelude.hxx>

using namespace std;
using namespace Prelude;

],      [return !!checkVersion(NULL); ],
        [ echo "*** The test program compiled, but did not run. This usually means"
	  echo "*** that the run-time linker is not finding LIBPRELUDE or finding the wrong"
          echo "*** version of LIBPRELUDE. If it is not finding LIBPRELUDE, you'll need to set your"
          echo "*** LD_LIBRARY_PATH environment variable, or edit /etc/ld.so.conf to point"
          echo "*** to the installed location  Also, make sure you have run ldconfig if that"
          echo "*** is required on your system"
          echo "***"
          echo "*** If you have an old version installed, it is best to remove it, although"
          echo "*** you may also be able to get things to work by modifying LD_LIBRARY_PATH"
          echo "***" ],
        [ echo "*** The test program failed to compile or link. See the file config.log for the"
          echo "*** exact error that occured. This usually means LIBPRELUDE was incorrectly installed"
          echo "*** or that you have moved LIBPRELUDE since it was installed. In the latter case, you"
          echo "*** may want to edit the libprelude-config script: $LIBPRELUDE_CONFIG" ])
          CFLAGS="$ac_save_CFLAGS"
          LDFLAGS="$ac_save_LDFLAGS"
          LIBS="$ac_save_LIBS"
       fi
     fi
     LIBPRELUDE_CFLAGS=""
     LIBPRELUDE_LDFLAGS=""
     LIBPRELUDE_LIBS=""
     ifelse([$3], , :, [$3])
  fi
  rm -f conf.libpreludetest
  AC_SUBST(LIBPRELUDE_CFLAGS)
  AC_SUBST(LIBPRELUDE_PTHREAD_CFLAGS)
  AC_SUBST(LIBPRELUDE_LDFLAGS)
  AC_SUBST(LIBPRELUDE_LIBS)
  AC_SUBST(LIBPRELUDE_PREFIX)
  AC_SUBST(LIBPRELUDE_CONFIG_PREFIX)

  m4_ifdef([LT_INIT],
           [AC_DEFINE([PRELUDE_APPLICATION_USE_LIBTOOL2], [], [Define whether application use libtool >= 2.0])],
           [])

])

dnl *-*wedit:notab*-*  Please keep this as the last line.

