#include "gcm.h"
#include "dh.h"
#include "sign.h"

struct header {
	enum MSG_TYPE type;
	unsigned int block_num;
	unsigned int total_blocks;
};

struct message {
	struct header header;
	unsigned char body[];
};

static unsigned char receive_buffer[2048];

size_t proto_receive(enum MSG_TYPE *type, void *buffer)
{
}

size_t proto_send(struct message message)
{
}
