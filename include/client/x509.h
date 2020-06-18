#ifndef CLIENT_X509_H
#define CLIENT_X509_H

#include <openssl/x509.h>
#include <stdbool.h>
#include <stddef.h>

X509 *x509_deserialize(const unsigned char *data, size_t len);
X509_CRL *x509_read_crl(const char *filename);
char *x509_get_name_oneline(const X509 *cert);
bool x509_verify(X509 *cert, X509 *ca, X509_CRL *crl);

#endif /* CLIENT_X509_H */
