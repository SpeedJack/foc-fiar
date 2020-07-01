#ifndef COMMON_ERROR_H
#define COMMON_ERROR_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdnoreturn.h>

enum __attribute__((packed)) error_code {
	ENOERR, EALLOC, EFILE, ENET, ETIMEOUT, ECONNCLOSE, EINVMSG, ETOOBIG,
	EREPLAY, EINVHASH, EINVSIG, EGCM, ETOOMUCH, EINVCERT, EPEERERR,
	EOSSL, EUNSPEC, ENOREG, ENOUSER, EINVMOVE, EINVMSG_P, EUNSPEC_P
};

extern void error_clear(void);
extern enum error_code error_get(void);
extern enum error_code error_get_net_code(void);
extern void error_vsetf(enum error_code c, const char *format, va_list ap);
extern void error_setf(enum error_code c, const char *format, ...);
extern void error_set(enum error_code c, const char *msg);
extern char *error_get_message(void);
extern void error_print(void);
extern noreturn void panic(const char *errstr);
extern noreturn void panicf(const char *format, ...);
extern void error_set_autoprint(bool value);

static inline void error_enable_autoprint(void)
{
	error_set_autoprint(true);
}

static inline void error_disable_autoprint(void)
{
	error_set_autoprint(false);
}

#define _REPORT_ERR(code, msg, file, func, line)			\
	error_setf(code, (msg && *(char *)(msg) != '\0')		\
			? "%s:%d:%s(): %s"				\
			: "Error reported by %3$s() at %1$s:%2$d.",	\
		file, line, func, msg)

#define REPORT_ERR(code, msg)						\
	_REPORT_ERR(code, msg, __FILE__ , __func__, __LINE__)

#endif /* COMMON_ERROR_H */
