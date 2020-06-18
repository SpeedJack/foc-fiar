#ifndef COMMON_ERROR_H
#define COMMON_ERROR_H

#include <stdarg.h>

enum error_code {
	ENOERR,
	EALLOC,
	EFILE,
	ENET,
	EREPLAY,
	EINVACK,
	EINVSIG,
	EGCM,
	EOSSL,
	EUNSPEC
};

extern void error_clear(void);
extern enum error_code error_get(void);
extern void error_vsetf(enum error_code c, const char *format, va_list ap);
extern void error_setf(enum error_code c, const char *format, ...);
extern void error_set(enum error_code c, const char *msg);
extern void error_print(void);
extern void error_enable_autoprint(void);
extern void error_disable_autoprint(void);

#define _REPORT_ERR(func, code, msg)	error_setf(code, "%s: %s", func, msg)
#define REPORT_ERR(code, msg)		_REPORT_ERR(__func__, code, msg)

#endif /* COMMON_ERROR_H */
