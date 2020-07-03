#include "server/clientlist.h"
#include "server/list.h"
#include "assertions.h"
#include "error.h"
#include <arpa/inet.h>
#include <string.h>

#include <stdio.h>

struct list_item {
	struct client client;
	struct list_head head;
	struct list_head thead;
};

static LIST_HEAD(client_list);
static LIST_HEAD(unregistered);

#define HASHTABLE_SIZE		32
#define HASH(sock)		sock % HASHTABLE_SIZE

static struct list_head table[HASHTABLE_SIZE];

void clientlist_init(void)
{
	for (unsigned int i = 0; i < HASHTABLE_SIZE; i++)
		INIT_LIST_HEAD(&table[i]);
}

struct client *clientlist_insert(struct client client)
{
	struct list_item *item = OPENSSL_malloc(sizeof(struct list_item));
	if (!item) {
		REPORT_ERR(EALLOC, "Can not allocate space for the client structure.");
		return NULL;
	}
	INIT_LIST_HEAD(&item->head);
	INIT_LIST_HEAD(&item->thead);
	memcpy(&item->client, &client, sizeof(struct client));
	list_add(&item->head, &unregistered);
	list_add(&item->thead, &table[HASH(item->client.socket)]);
	if (*client.username != '\0' && !clientlist_register(&item->client))
		return NULL;
	return &item->client;
}

bool clientlist_register(struct client *client)
{
	if (*client->username == '\0') {
		REPORT_ERR(EUNSPEC, "No username specified.");
		return false;
	}
	struct list_item *it;
	list_for_each_entry(it, &unregistered, head)
		if (&it->client == client)
			break;
	if (&it->client != client) {
		REPORT_ERR(EUNSPEC, "Can not find client to register.");
		return false;
	}
	if (clientlist_search(client->username)) {
		REPORT_ERR(EUNSPEC, "User with this username already registered.");
		return false;
	}
	list_del(&it->head);
	if (list_empty(&client_list)) {
		list_add(&it->head, &client_list);
		return true;
	}
	struct list_item *cur;
	int diff = 0;
	list_for_each_entry(cur, &client_list, head) {
		diff = strcmp(cur->client.username, client->username);
		if (diff > 0 || cur->head.next == &client_list)
			break;
	}
	if (diff > 0)
		list_add_tail(&it->head, &cur->head);
	else
		list_add(&it->head, &cur->head);
	return true;
}

struct user_list *clientlist_get_user_list(struct client *exclude)
{
	int count = list_count(&client_list) - 1;
	struct user_list *lst = OPENSSL_zalloc(sizeof(struct user_list)
		+ sizeof(struct user)*count);
	if (!lst) {
		REPORT_ERR(EALLOC, "Can not allocate space for the user list data structure.");
		return NULL;
	}
	lst->count = (uint32_t)count;
	struct list_item *cur;
	int num = 0;
	list_for_each_entry(cur, &client_list, head) {
		if (&cur->client == exclude)
			continue;
		struct user *user = (struct user *)(((char *)lst)
			+ sizeof(struct user_list) + num*sizeof(struct user));
		strcpy(user->username, cur->client.username);
		user->in_game = cur->client.opponent != NULL;
		num++;
	}
	assert(num == count);
	return lst;

}

struct client *clientlist_add(PROTO_CTX *ctx, int socket, struct sockaddr *addr)
{
	struct client client;
	memset(&client, 0, sizeof(struct client));
	switch (addr->sa_family) {
		case AF_INET:
			inet_ntop(AF_INET,
				&(((struct sockaddr_in *)addr)->sin_addr),
				client.address, ADDRSTRLEN);
			break;
		case AF_INET6:
			inet_ntop(AF_INET6,
				&(((struct sockaddr_in6 *)addr)->sin6_addr),
				client.address, ADDRSTRLEN);
			break;
		default:
			REPORT_ERR(EUNSPEC, "Invalid address family.");
			return NULL;
	}
	client.socket = socket;
	client.ctx = ctx;
	client.in_game = false;
	client.opponent = NULL;
	client.pubkey = NULL;
	return clientlist_insert(client);
}

struct client *clientlist_get(int socket)
{
	struct list_item *cur;
	list_for_each_entry(cur, &table[HASH(socket)], thead)
		if (cur->client.socket == socket)
			return &cur->client;
	return NULL;
}

struct client *clientlist_search(const char username[MAX_USERNAME_LEN + 1])
{
	struct list_item *cur;
	list_for_each_entry(cur, &client_list, head)
		if (strcmp(cur->client.username, username) == 0)
			return &cur->client;
	return NULL;
}

int clientlist_getfdset(fd_set *set)
{
	int highest = 0;
	FD_ZERO(set);
	struct list_item *cur;
	list_for_each_entry(cur, &client_list, head) {
		FD_SET(cur->client.socket, set);
		highest = cur->client.socket > highest
			? cur->client.socket : highest;
	}
	list_for_each_entry(cur, &unregistered, head) {
		FD_SET(cur->client.socket, set);
		highest = cur->client.socket > highest
			? cur->client.socket : highest;
	}
	return highest;
}

static void remove_item(struct list_item *item)
{
	struct list_item *cur;
	list_for_each_entry(cur, &client_list, head)
		if (cur->client.opponent == &item->client) {
			cur->client.in_game = false;
			cur->client.opponent = NULL;
		}
	list_del(&item->head);
	list_del(&item->thead);
	if (item->client.ctx)
		proto_ctx_free(item->client.ctx);
	OPENSSL_free(item);
}

void clientlist_remove(struct client *client)
{
	struct list_item *cur;
	list_for_each_entry(cur, &table[HASH(client->socket)], thead) {
		if (&cur->client != client)
			continue;
		remove_item(cur);
		return;
	}
}

static void clientlist_freelist(struct list_head *list)
{
	struct list_item *cur;
	struct list_item *toremove = NULL;
	list_for_each_entry(cur, list, head) {
		if (toremove)
			remove_item(toremove);
		toremove = cur;
	}
	if (toremove)
		remove_item(toremove);
}

void clientlist_free(void)
{
	clientlist_freelist(&unregistered);
	clientlist_freelist(&client_list);
}
