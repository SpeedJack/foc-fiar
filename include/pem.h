#ifndef COMMON_PEM_H
#define COMMON_PEM_H

#include <openssl/evp.h>
#include <openssl/pem.h>

extern EVP_PKEY *pem_read_privkey(const char *filename, pem_password_cb *cb);
extern EVP_PKEY *pem_read_pubkey(const char *filename);
extern X509 *pem_read_x509_file(const char *filename);
extern unsigned char *pem_serialize_pubkey(EVP_PKEY *key, size_t *len);
extern EVP_PKEY *pem_deserialize_pubkey(unsigned char *key, size_t len);

#endif /* COMMON_PEM_H */
