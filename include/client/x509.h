#ifndef CLIENT_X509_H
#define CLIENT_X509_H

#include <openssl/x509.h>
#include <stdbool.h>
#include <stddef.h>

bool x509_store_init(const char *cafile, const char *crlfile);
X509 *x509_deserialize(const unsigned char *data, size_t len);
X509_CRL *x509_read_crl(const char *filename);
EVP_PKEY *x509_extract_pubkey(X509* cert);
char *x509_get_name_oneline(const X509 *cert);
bool x509_verify(X509 *cert);
void x509_store_free(void);

#endif /* CLIENT_X509_H */
