#include "client/x509.h"
#include "assertions.h"
#include "error.h"
#include "memdbg.h"
#include "pem.h"
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <string.h>

static const char *subject_name = "/C=IT/CN=Server";
static X509 *ca_cert;
static X509_CRL *crl;
static X509_STORE *store;

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

EVP_PKEY *x509_extract_pubkey(X509 *cert)
{
	assert(cert);
	EVP_PKEY *pubkey = X509_get_pubkey(cert);
	if (!pubkey)
		REPORT_ERR(EOSSL, "X509_get_pubkey() returned NULL.");
	return pubkey;
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
	memdbg_register_alloc(name, strlen(name) + 1);
	if (!name)
		return false;
	int res = strcmp(name, subject_name);
	OPENSSL_free(name);
	if (res != 0)
		REPORT_ERR(EINVCERT, "Invalid subject name.");
	return res == 0;
}

bool x509_store_init(const char *cafile, const char *crlfile)
{
	ca_cert = pem_read_x509_file(cafile);
	if (!ca_cert)
		return false;
	crl = x509_read_crl(crlfile);
	if (!crl) {
		X509_free(ca_cert);
		return false;
	}
	store = X509_STORE_new();
	if (!store) {
		REPORT_ERR(EOSSL, "X509_STORE_new() returned NULL.");
		x509_store_free();
		return false;
	}
	if (X509_STORE_add_cert(store, ca_cert) != 1) {
		REPORT_ERR(EOSSL, "X509_STORE_add_cert() failed.");
		x509_store_free();
		return false;
	}
	if (X509_STORE_add_crl(store, crl) != 1) {
		REPORT_ERR(EOSSL, "X509_STORE_add_crl() failed.");
		x509_store_free();
		return false;
	}
	if (X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK) != 1) {
		REPORT_ERR(EOSSL, "X509_STORE_set_flags() failed.");
		x509_store_free();
		return false;
	}
	return true;
}

void x509_store_free(void)
{
	if (store)
		X509_STORE_free(store);
	if (ca_cert)
		X509_free(ca_cert);
	if (crl)
		X509_CRL_free(crl);
}

bool x509_verify(X509 *cert)
{
	assert(cert);
	X509_STORE_CTX *ctx = X509_STORE_CTX_new();
	if (!ctx) {
		REPORT_ERR(EOSSL, "X509_STORE_CTX_new() returned NULL.");
		return false;
	}
	if (X509_STORE_CTX_init(ctx, store, cert, NULL) != 1) {
		REPORT_ERR(EOSSL, "X509_STORE_CTX_init() failed.");
		X509_STORE_CTX_free(ctx);
		return false;
	}
	int res = X509_verify_cert(ctx);
	if (res != 1)
		REPORT_ERR(EINVCERT, X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
	X509_STORE_CTX_free(ctx);
	return res == 1 && x509_verify_name(cert);
}
