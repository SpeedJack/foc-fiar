#include "error.h"
#include "cout.h"
#include <openssl/err.h>
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
	[ETIMEOUT]	= "[ETIMEOUT] Request timed out.",
	[ECONNCLOSE]	= "[ECONNCLOSE] Peer has closed the connection.",
	[EINVMSG]	= "[EINVMSG] Received an invalid message.",
	[ETOOBIG]	= "[ETOOBIG] Received message is too big.",
	[EREPLAY]	= "[EREPLAY] Received a replayed message.",
	[EINVHASH]	= "[EINVHASH] The received message does not specify the correct hash of the last message.",
	[EINVSIG]	= "[EINVSIG] Received a message signed with an invalid signature.",
	[EGCM]		= "[EGCM] Error while encrypting/decrypting a GCM message.",
	[ETOOMUCH]	= "[ETOOMUCH] Performed too much GCM operations, restart the application to reinitialize GCM key and IV.",
	[EINVCERT]	= "[EINVCERT] Server certificate is not valid.",
	[EPEERERR]	= "[EPEERERR] Received an error message from peer.",
	[EOSSL]		= "[EOSSL] Unknown OpenSSL error.",
	[EUNSPEC]	= "[EUNSPEC] Unknown error.",
	[ENOREG]	= "You are not registered in the system.",
	[ENOUSER]	= "The specified user does not exists.",
	[EINVMOVE]	= "Opponent says that your move is not valid.",
	[EINVMSG_P]	= "[EINVMSG] Peer says that the last sent message was invalid.",
	[EUNSPEC_P]	= "[EUNSPEC] Peer encountered an unexpected error."
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
	if (errmsg)
		OPENSSL_free(errmsg);
	errmsg = NULL;
	errno = 0;
}

enum error_code error_get(void)
{
	return code;
}

enum error_code error_get_net_code(void)
{
	switch (code) {
	case ENOERR:
		return ENOERR;
	case EINVMSG:
	case ETOOBIG:
	case EREPLAY:
	case EINVHASH:
	case EINVSIG:
	case EGCM:
		return EINVMSG_P;
	default:
		return EUNSPEC_P;
	}
}

void error_vsetf(enum error_code c, const char *format, va_list ap)
{
	errnum = errno;
	error_clear();
	code = c;
	if (!format || *format == '\0')
		return;
	errmsg = OPENSSL_malloc(ERRMSG_BUF_SIZE);
	if (!errmsg) {
		cout_printf_error("error_vsetf: Can not allocate space for error message.\n"
			"\tMessage: %s\n", format);
		return;
	}
	vsnprintf(errmsg, ERRMSG_BUF_SIZE, format, ap);
	errmsg[ERRMSG_BUF_SIZE - 1] = '\0';
	if (autoprint)
		error_print();
}

void error_setf(enum error_code c, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	error_vsetf(c, format, args);
	va_end(args);
}

void error_set(enum error_code c, const char *msg)
{
	errnum = errno;
	error_clear();
	code = c;
	if (!msg || *msg == '\0')
		return;
	errmsg = OPENSSL_strdup(msg);
	if (!errmsg) {
		cout_printf_error("error_set: Can not allocate space for error message.\n"
			"\tMessage: %s\n", msg);
		return;
	}
	if (autoprint)
		error_print();
}

char *error_get_message(void)
{
	char *msg = OPENSSL_memdup(errmsg, strlen(errmsg) + 1);
	if (!msg) {
		cout_printf_error("error_get_message: Can not allocate space for error message.\n"
			"\tMessage: %s\n", msg);
		return NULL;
	}
	return msg;
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

void error_set_autoprint(bool value)
{
	autoprint = value;
}

/* Prints an error and exits with EXIT_FAILURE. */
noreturn void panic(const char *errstr)
{
	cout_print_error(errstr);
	exit(EXIT_FAILURE);
}

/* Formats and prints an error, then it exits with EXIT_FAILURE. */
noreturn void panicf(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	cout_vprintf_error(format, args);
	exit(EXIT_FAILURE);
}
