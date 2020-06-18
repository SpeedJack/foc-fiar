#include "server/x509.h"
#include "error.h"
#include <assert.h>

unsigned char *x509_serialize_cert(X509 *cert, size_t *len)
{
	assert(cert && len);
	unsigned char *buf = NULL;
	int size = i2d_X509(cert, &buf);
	if (size < 0 || !buf) {
		REPORT_ERR(EOSSL, "i2d_X509() failed.");
		return NULL;
	}
	*len = size;
	return buf;
}
