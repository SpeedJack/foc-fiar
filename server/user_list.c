#include "list.h"

struct user_details {
	char username[];
};

struct user {
	struct sockaddr_storage sockaddr;	
	struct sockaddr_storage p2psockaddr;
	EVP_PKEY *pubkey;
	struct user_details details;
};

void add_user(struct user user)
{
}
