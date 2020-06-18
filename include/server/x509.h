#ifndef SERVER_X509_H
#define SERVER_X509_H

#include <openssl/x509.h>
#include <stddef.h>

extern unsigned char *x509_serialize_cert(X509 *cert, size_t *len);

#endif /* SERVER_X509_H */
