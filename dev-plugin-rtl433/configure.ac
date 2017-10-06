AC_INIT

AC_CONFIG_SRCDIR([capture_rtl433.c])

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

AC_CHECK_PROG(havepkgconfig, [pkg-config], yes, no)
if test "$havepkgconfig" = "no"; then
    AC_MSG_ERROR([Missing pkg-config which is required for checking other packages])
fi

PKG_CHECK_MODULES(librtlsdr, [librtlsdr], havertlsdr=yes, havertlsdr=no)
if test "$havertlsdr" = "no"; then
    AC_MSG_ERROR([Missing librtlsdr])
fi

RTLCFLAGSS=`pkg-config --cflags librtlsdr`
RTLLIBS=`pkg-config --libs librtlsdr`

AC_SUBST(RTLCFLAGS)
AC_SUBST(RTLLIBS)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT


