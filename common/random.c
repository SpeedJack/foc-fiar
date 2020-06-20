#include "random.h"
#include <openssl/rand.h>

void random_init(void)
{
	RAND_poll();
}

uint32_t random_nonce(void)
{
	uint32_t nonce;
	if (RAND_bytes((unsigned char *)&nonce, sizeof(uint32_t)) != 1)
		return 0;
	return nonce;
}
