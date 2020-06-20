#ifndef COMMON_ERROR_H
#define COMMON_ERROR_H

#include <stdarg.h>
#include <stdbool.h>

enum error_code {
	ENOERR, EALLOC, EFILE, ENET, EINVMSG, EREPLAY, EINVACK, EINVSIG,
	EGCM, EINVCERT, EPEERERR, EOSSL, EUNSPEC
};

extern void error_clear(void);
extern enum error_code error_get(void);
extern void error_vsetf(enum error_code c, const char *format, va_list ap);
extern void error_setf(enum error_code c, const char *format, ...);
extern void error_set(enum error_code c, const char *msg);
extern void error_print(void);
extern void error_set_autoprint(bool value);

static inline void error_enable_autoprint()
{
	error_set_autoprint(true);
}

static inline void error_disable_autoprint()
{
	error_set_autoprint(false);
}

#define _REPORT_ERR(code, msg, file, func, line) ({			\
	if (msg)							\
		error_setf(code, "%s:%d:%s(): %s",			\
			file, line, func, msg);				\
	else								\
		error_setf(code, "Error reported by %s() at %s:%d.",	\
			func, file, line);				\
	})
#define REPORT_ERR(code, msg)						\
	_REPORT_ERR(code, msg, __FILE__ , __func__, __LINE__)

#endif /* COMMON_ERROR_H */
