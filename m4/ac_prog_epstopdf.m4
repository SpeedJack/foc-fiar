#
# AC_PROG_EPSTOPDF
#
# Test for epstopdf
# and set $epstopdf to the correct value.
#
#
dnl @synopsis AC_PROG_EPSTOPDF
dnl
dnl This macro test if epstopdf is installed. If epstopdf
dnl is installed, it set $epstopdf to the right value
dnl
dnl @version 1.3
dnl @author Niccolò Scatena speedjack95@gmail.com
dnl
AC_DEFUN([AC_PROG_EPSTOPDF],[
AC_CHECK_PROGS(epstopdf,epstopdf,no)
export epstopdf;
if test $epstopdf = "no" ;
then
	AC_MSG_ERROR([Unable to find a epstopdf application]);
fi
AC_SUBST(epstopdf)
])
