#include "random.h"
#include "error.h"
#include <openssl/rand.h>
#include <stdbool.h>

static bool random_init(void)
{
	if (RAND_status() == 1)
		return true;
	bool res = !!RAND_poll();
	if (!res)
		REPORT_ERR(EOSSL, "RAND_pool() failed.");
	return res;
}

uint32_t random_nonce(void)
{
	if (!random_init())
		return 0;
	uint32_t nonce;
	do {
		if (RAND_bytes((unsigned char *)&nonce, sizeof(uint32_t)) != 1) {
			REPORT_ERR(EOSSL, "RAND_bytes() failed.");
			return 0;
		}
	} while (nonce == 0);
	return nonce;
}
