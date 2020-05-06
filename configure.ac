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

# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB
AM_PROG_AR

if test "x$colors" = "xyes"; then
	AC_DEFINE([ENABLE_COLORS], [1], [Define if colored output should be
		enabled when printing the game board.])
fi

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

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h limits.h stddef.h stdint.h stdlib.h string.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_UINT16_T

# Checks for library functions.
AC_CHECK_FUNCS([memset strerror strtol])

AC_CONFIG_FILES([Makefile
		common/Makefile
		client/Makefile
		doc/Makefile])

AC_OUTPUT
