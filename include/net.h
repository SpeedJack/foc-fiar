#ifndef COMMON_NET_H
#define COMMON_NET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

extern int net_udp_bind(uint16_t port);
extern int net_listen(uint16_t port, int socktype);
extern int net_accept(int socket);
extern struct addrinfo *net_getaddrinfo(const char *node, const char *port,
	int family, int socktype);
extern int net_connect(struct addrinfo info);
extern bool net_recv(int socket, void *buf, size_t len, int flags);
extern bool net_sendto(int socket, const void *buf, size_t len, int flags,
	struct addrinfo *info);
extern bool net_send(int socket, const void *buf, size_t len, int flags);

#endif /* COMMON_NET_H */
