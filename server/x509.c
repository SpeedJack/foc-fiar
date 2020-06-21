#include "server/x509.h"
#include "assertions.h"
#include "error.h"
#include "memdbg.h"

unsigned char *x509_serialize_cert(X509 *cert, size_t *len)
{
	assert(cert && len);
	unsigned char *buf = NULL;
	int size = i2d_X509(cert, &buf);
	memdbg_register_alloc(buf, size);
	if (size < 0 || !buf) {
		REPORT_ERR(EOSSL, "i2d_X509() failed.");
		return NULL;
	}
	*len = size;
	return buf;
}
