#include "random.h"
#include <openssl/rand.h>

void rand_init()
{
	RAND_poll();
}

uint32_t random_nonce()
{
	uint32_t nonce;
	if (RAND_bytes((unsigned char *)&nonce, sizeof(uint32_t)) != 1)
		return 0;
	return nonce;
}
