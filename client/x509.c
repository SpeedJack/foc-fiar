#include "client/x509.h"
#include "error.h"
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <assert.h>
#include <string.h>

static const char *subject_name = "CN=cybersec";

X509 *x509_deserialize(const unsigned char *data, size_t len)
{
	assert(data);
	X509 *cert = d2i_X509(NULL, &data, len);
	if (!cert)
		REPORT_ERR(EOSSL, "d2i_X509() returned NULL.");
	return cert;
}

X509_CRL *x509_read_crl(const char *filename)
{
	assert(filename);
	FILE *fp = fopen(filename, "rb");
	if (!fp) {
		REPORT_ERR(EFILE, "fopen() failed.");
		return NULL;
	}
	X509_CRL *crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL);
	fclose(fp);
	if (!crl)
		REPORT_ERR(EOSSL, "PEM_read_X509_crl() returned NULL.");
	return crl;
}

char *x509_get_name_oneline(const X509 *cert)
{
	assert(cert);
	X509_NAME *name = X509_get_subject_name(cert);
	if (!name) {
		REPORT_ERR(EOSSL, "X509_get_subject_name() returned NULL.");
		return NULL;
	}
	char *oneline = X509_NAME_oneline(name, NULL, 0);
	if (!oneline) {
		REPORT_ERR(EOSSL, "X509_NAME_oneline() returned NULL.");
		return NULL;
	}
	return oneline;
}

static bool x509_verify_name(const X509 *cert)
{
	char *name = x509_get_name_oneline(cert);
	if (!name)
		return false;
	int res = strcmp(name, subject_name);
	free(name);
	if (res != 0)
		REPORT_ERR(EINVCERT, "Invalid subject name.");
	return res == 0;
}

bool x509_verify(X509 *cert, X509 *ca, X509_CRL *crl)
{
	assert(cert && ca && crl);
	X509_STORE *store = X509_STORE_new();
	X509_STORE_CTX *ctx = NULL;
	if (!store) {
		REPORT_ERR(EOSSL, "X509_STORE_new() returned NULL.");
		return false;
	}
	if (X509_STORE_add_cert(store, ca) != 1) {
		REPORT_ERR(EOSSL, "X509_STORE_add_cert() failed.");
		goto clean_return_error;
	}
	if (X509_STORE_add_crl(store, crl) != 1) {
		REPORT_ERR(EOSSL, "X509_STORE_add_crl() failed.");
		goto clean_return_error;
	}
	if (X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK) != 1) {
		REPORT_ERR(EOSSL, "X509_STORE_set_flags() failed.");
		goto clean_return_error;
	}
	ctx = X509_STORE_CTX_new();
	if (!ctx) {
		REPORT_ERR(EOSSL, "X509_STORE_new() returned NULL.");
		goto clean_return_error;
	}
	if (X509_STORE_CTX_init(ctx, store, cert, NULL) != 1) {
		REPORT_ERR(EOSSL, "X509_STORE_CTX_init() failed.");
		goto clean_return_error;
	}
	int res = X509_verify_cert(ctx);
	if (res != 1)
		REPORT_ERR(EINVCERT, X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));

	X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);

	return res == 1 && x509_verify_name(cert);
clean_return_error:
	if (ctx)
		X509_STORE_CTX_free(ctx);
	X509_STORE_free(store);
	return false;

}
