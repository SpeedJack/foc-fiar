#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([foc-fiar], [1.0.0], [https://github.com/SpeedJack/foc-fiar])
AC_CONFIG_SRCDIR([client/client.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign -Wall -Werror])

AC_ARG_ENABLE([latex-doc],
	[AS_HELP_STRING([--disable-latex-doc], [disable building the PDF
		documentation from LaTeX source])],
	[latexdoc=no],
	[latexdoc=yes])

AC_ARG_ENABLE([colors],
	[AS_HELP_STRING([--disable-colors], [disable colored output when
		printing the game board])],
	[colors=no],
	[colors=yes])

AC_ARG_ENABLE([assertions],
	[AS_HELP_STRING([--enable-assertions], [enable assertions in code])],
	[assertions=yes],
	[assertions=no])

AC_ARG_ENABLE([warnings],
	[AS_HELP_STRING([--enable-warnings], [enable all compiler warnings])],
	[warnings=yes],
	[warnings=no])

AC_ARG_ENABLE([debug],
	[AS_HELP_STRING([--enable-debug], [include debug symbols and disable
		optimization])],
	[debug=yes],
	[debug=no])

# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB
AM_PROG_AR

if test "x$latexdoc" = "xyes"; then
	AC_PROG_LATEXMK
	AC_PROG_PDFLATEX
	AC_PROG_BIBTEX
	AC_PROG_EPSTOPDF
	AC_LATEX_CLASS_REPORT
	AC_LATEX_PACKAGE_FONTENC
	AC_LATEX_PACKAGE_AMSMATH
	AC_LATEX_PACKAGES_REQUIRE([babel, inputenc, lmodern, csquotes,
		microtype, geometry, etoolbox, suffix, minibox, pdflscape,
		xcolor, graphicx, titlesec, caption, interval, array,
		makecell, enumitem, listings, nameref, varioref, hyperref,
		biblatex])
fi
AM_CONDITIONAL([BUILD_DOC], [test -n "$LATEXMK"])

# Checks for libraries.
AC_CHECK_LIB([crypto], [CRYPTO_new_ex_data])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h limits.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/socket.h termios.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset socket strerror strtol])

# Add config constants
if test "x$colors" = "xyes"; then
	AC_DEFINE([ENABLE_COLORS], [1], [Define if colored output should be
		enabled when printing the game board.])
fi

if test "x$assertions" = "xno"; then
	AC_DEFINE([NDEBUG], [1], [Disable assertions.])
fi

# Checks for compiler flags
if test "x$warnings" = "xyes"; then
	CC_CHECK_CFLAGS_APPEND([-Wall -Wextra], [], [])
fi

if test "x$debug" = "xyes"; then
	CC_CHECK_CFLAGS_APPEND([-O0 -Og -g -g3 -ggdb3], [], [])
	AC_DEFINE([DEBUG_CODE], [1], [Enable debug code.])
else
	CC_CHECK_CFLAG_APPEND([-O2])
fi

CC_ATTRIBUTE_PACKED
CC_ATTRIBUTE_UNUSED

AC_CONFIG_FILES([Makefile
		client/Makefile
		common/Makefile
		doc/Makefile
		server/Makefile])

AC_OUTPUT
