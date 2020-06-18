#include "pem.h"
#include "error.h"
#include <openssl/bio.h>
#include <assert.h>
#include <string.h>

EVP_PKEY *pem_read_privkey(const char *filename, pem_password_cb *cb)
{
	FILE *fp = fopen(filename, "rb");
	if (!fp) {
		REPORT_ERR(EFILE, "fopen() failed.");
		return NULL;
	}
	EVP_PKEY *privkey = PEM_read_PrivateKey(fp, NULL, cb, NULL);
	fclose(fp);
	if (!privkey) {
		REPORT_ERR(EOSSL, "PEM_read_PrivateKey() returned NULL.");
		return NULL;
	}
	return privkey;
}

EVP_PKEY *pem_read_pubkey(const char *filename)
{
	FILE *fp = fopen(filename, "rb");
	if (!fp) {
		REPORT_ERR(EFILE, "fopen() failed.");
		return NULL;
	}
	EVP_PKEY *pubkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
	fclose(fp);
	if (!pubkey) {
		REPORT_ERR(EOSSL, "PEM_read_PUBKEY() returned NULL.");
		return NULL;
	}
	return pubkey;
}

unsigned char *pem_serialize_pubkey(EVP_PKEY *key, size_t *len)
{
	assert(key && len);
	BIO *bio = BIO_new(BIO_s_mem());
	if (!bio) {
		REPORT_ERR(EOSSL, "BIO_new() returned NULL.");
		return NULL;
	}
	if (PEM_write_bio_PUBKEY(bio, key) != 1) {
		REPORT_ERR(EOSSL, "BIO_write_bio_PUBKEY() failed.");
		BIO_free(bio);
		return NULL;
	}
	unsigned char *pubkey;
	*len = BIO_get_mem_data(bio, &pubkey);
	if (*len <= 0 || !pubkey) {
		REPORT_ERR(EOSSL, "BIO_get_mem_data() failed.");
		BIO_free(bio);
		return NULL;
	}
	BIO_set_close(bio, BIO_NOCLOSE);
	BIO_free(bio);
	return pubkey;
}

EVP_PKEY *pem_deserialize_pubkey(unsigned char *key, size_t len)
{
	assert(key);
	BIO *bio = BIO_new(BIO_s_mem());
	if (!bio) {
		REPORT_ERR(EOSSL, "BIO_new() returned NULL.");
		return NULL;
	}
	if (BIO_write(bio, key, len) != (int)len) {
		REPORT_ERR(EOSSL, "BIO_write() failed.");
		BIO_free(bio);
		return NULL;
	}
	EVP_PKEY *pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	if (!pubkey) {
		REPORT_ERR(EOSSL, "PEM_read_bio_PUBKEY() returned NULL.");
		BIO_free(bio);
		return NULL;
	}
	BIO_set_close(bio, BIO_NOCLOSE); /* needed? */
	BIO_free(bio);
	return pubkey;
}
