struct msg_header {
	uint32_t magic;
	uint32_t counter;
	enum msg_type type;
	uint32_t payload_size;
	uint32_t nonce;
	unsigned char prev_hash[32];
};
