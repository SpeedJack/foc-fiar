#ifndef COMMON_NET_H
#define COMMON_NET_H

#include <sys/socket.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

extern bool net_set_timeout(int sfd, unsigned long millis);
extern int net_udp_bind(uint16_t port);
extern int net_listen(uint16_t port, int socktype);
extern int net_accept(int socket, struct sockaddr *addr, socklen_t *addrlen);
extern struct addrinfo *net_getaddrinfo(const char *node, const char *port,
	int family, int socktype);
extern int net_connect(struct addrinfo info);
extern void net_close(int socket);
extern void net_set_nonblocking(bool noblock);
extern bool net_recv(int socket, void *buf, size_t len);
extern bool net_send(int socket, const void *buf, size_t len,
	struct addrinfo *info);

#endif /* COMMON_NET_H */
