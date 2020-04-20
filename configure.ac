#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([foc-fiar], [1.0.0], [https://github.com/SpeedJack/foc-fiar])
AC_CONFIG_SRCDIR([client/main.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([foreign -Wall -Werror])

# The user can disable building of the PDF of the manual, for example
# if the required LaTeX packages are not installed
AC_ARG_ENABLE([latex-doc],
	[AS_HELP_STRING([--disable-latex-doc], [disable building the PDF
	documentation from LaTeX source])],
	[latexdoc=no],
	[latexdoc=yes])

# Checks for programs.
AC_PROG_CC
AC_PROG_RANLIB
AM_PROG_AR

if test "x$latexdoc" = "xyes"; then
	AC_PROG_LATEXMK
	AC_PROG_PDFLATEX
	AC_LATEX_CLASS_REPORT
	AC_LATEX_PACKAGE_FONTENC
	AC_LATEX_PACKAGE_AMSMATH
	AC_PROG_BIBTEX
fi
AM_CONDITIONAL([BUILD_DOC], [test -n "$LATEXMK"])

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([stddef.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE

# Checks for library functions.

AC_CONFIG_FILES([Makefile
		common/Makefile
		client/Makefile
		doc/Makefile])

AC_OUTPUT
