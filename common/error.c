#include "error.h"
#include "cout.h"
#include <openssl/err.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>

static enum error_code code = ENOERR;
static char *errmsg;
static int errnum;
static bool autoprint = false;

#define ERRMSG_BUF_SIZE		1024

static const char *errstr[] = {
	[ENOERR]	= "[ENOERR] No error. You should not see this message.",
	[EALLOC]	= "[EALLOC] An alloc operation failed. Out of memory?",
	[EFILE]		= "[EFILE] Error while opening a file.",
	[ENET]		= "[ENET] Network error.",
	[EREPLAY]	= "[EREPLAY] Received a replayed message. You may be under attack!",
	[EINVACK]	= "[EINVACK] Received an invalid ACK message.",
	[EINVSIG]	= "[EINVSIG] Received a message signed with an invalid signature.",
	[EGCM]		= "[EGCM] Error while encrypting/decrypting a GCM message.",
	[EOSSL]		= "[EOSSL] Unknown OpenSSL error.",
	[EUNSPEC]	= "[EUNSPEC] Unknown error."
};

static int print_sslerror(const char *str, __attribute__((unused)) size_t len,
	__attribute__((unused)) void *u)
{
	cout_printf_error("OpenSSL Error: %s", str);
	return 1;
}

void error_clear(void)
{
	code = ENOERR;
	errno = 0;
	if (errmsg)
		free(errmsg);
	errmsg = NULL;
}

enum error_code error_get(void)
{
	return code;
}

void error_vsetf(enum error_code c, const char *format, va_list ap)
{
	errnum = errno;
	error_clear();
	code = c;
	if (!format || *format == '\0')
		return;
	errmsg = malloc(ERRMSG_BUF_SIZE);
	if (!errmsg) {
		cout_printf_error("error_vsetf: Can not allocate space for error message.\n"
				"\tMessage: %s\n", format);
		return;
	}
	vsnprintf(errmsg, ERRMSG_BUF_SIZE, format, ap);
	errmsg[ERRMSG_BUF_SIZE] = '\0';
	if (autoprint)
		error_print();
}

void error_setf(enum error_code c, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	error_vsetf(c, format, args);
}

void error_set(enum error_code c, const char *msg)
{
	errnum = errno;
	error_clear();
	code = c;
	if (!msg || *msg == '\0')
		return;
	errmsg = malloc(strlen(msg) + 1);
	if (!errmsg) {
		cout_printf_error("error_set: Can not allocate space for error message.\n"
				"\tMessage: %s\n", msg);
		return;
	}
	strcpy(errmsg, msg);
	if (autoprint)
		error_print();
}

void error_print(void)
{
	if (code == ENOERR)
		return;
	cout_print_error(errstr[code]);
	if (errmsg)
		cout_print_error(errmsg);
	ERR_print_errors_cb(print_sslerror, NULL);
	if (errnum)
		cout_printf_error("Standard Error (%d): %s.\n", errnum, strerror(errnum));
	errnum = 0;
	error_clear();
}

void error_enable_autoprint(void)
{
	autoprint = true;
}

void error_disable_autoprint(void)
{
	autoprint = false;
}
