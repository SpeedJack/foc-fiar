#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <stdbool.h>

bool cert_init(const char *ca_filename, const char *crl_filename, const char *cert_filename)
{
	X509* ca;
	FILE *fp = fopen(ca_filename, "r");
	ca = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);

	X509* cert;
	fp = fopen(cert_filename, "r");
	if(!fp)
		puts("Error");
	cert = PEM_read_X509(fp, NULL, NULL, NULL);
	fclose(fp);

	X509_CRL *crl;
	fp = fopen(crl_filename, "r");
	if(!fp)
		puts("Error");
	crl = PEM_read_X509_CRL(fp, NULL, NULL, NULL);
	fclose(fp);

	X509_STORE *store = X509_STORE_new();
	if (!store)
		puts("Error");
	int ret = X509_STORE_add_cert(store, ca);
	if (ret != 1)
		puts("Error");
	ret = X509_STORE_add_crl(store, crl);
	if (ret != 1)
		puts("Error");
	ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
	if (ret != 1)
		puts("Error");

	X509_STORE_free(store);

	X509_STORE_CTX *ctx = X509_STORE_CTX_new();
	X509_STORE_CTX_init(ctx, store, cert, NULL);
	int ret2 = X509_verify_cert(ctx);
	X509_STORE_CTX_free(ctx);
	return ret2 != 1;

}
