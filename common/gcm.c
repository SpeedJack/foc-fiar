//#include "random.h"
//#include "digest.h"
#include <stdio.h>
#include <string.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

unsigned int gcm_encrypt(const char *plaintext, unsigned int plaintext_len, char *ciphertext, char *digest)
{
    int ciphertext_len;
    int len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char key[128];
    unsigned char iv[96];
    unsigned char tag[16];
    //void *memcpy(void *str1, const void *str2, size_t n)

    memcpy(key, digest, sizeof(key));
    memcpy(iv, digest+128, sizeof(iv));

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv))
      puts("Error");
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
      puts("Error");
  	ciphertext_len += len;
  	if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
      puts("Error");
    ciphertext_len += len;
  	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
      puts("Error");
  	EVP_CIPHER_CTX_free(ctx);

    return 0;
}

unsigned int gcm_decrypt(const char *ciphertext, unsigned int ciphertext_len, char *decryptedtext, char *digest)
{
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

  unsigned char key[128];
  unsigned char iv[96];
  unsigned char tag[16];
  unsigned int plaintext_len;
  int len;

  memcpy(key, digest, sizeof(key));
  memcpy(iv, digest+128, sizeof(iv));

	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv))
    puts("Error");
	if(1 != EVP_DecryptUpdate(ctx, decryptedtext, &len, ciphertext, ciphertext_len))
    puts("Error");
	plaintext_len += len;
	if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
    puts("Error");

	int ret = EVP_DecryptFinal_ex(ctx, decryptedtext + len, &len);
	EVP_CIPHER_CTX_free(ctx);
	if (ret > 0) {
		puts("Success!");
		puts(decryptedtext);
    return 0;
	} else {
		puts("Failure!");
    return -1;
	}
}
