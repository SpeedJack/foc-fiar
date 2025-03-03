#include "net.h"
#include "assertions.h"
#include "error.h"
#include <netinet/in.h>
#include <sys/types.h>
#include <errno.h>
#include <netdb.h>
#include <string.h>
#include <unistd.h>

#include <stdio.h>

#define LISTEN_BACKLOG		SOMAXCONN
#define RECV_BUFFER_SIZE	(1<<16)

static unsigned char recv_buffer[RECV_BUFFER_SIZE];
static size_t avail_bytes = 0;
static bool nonblocking = false;

static inline int net_socket(int family, int socktype, int protocol)
{
	int sfd = socket(family, socktype, protocol);
	if (sfd == -1)
		REPORT_ERR(ENET, "socket() failed.");
	return sfd;
}

static int net_bind(uint16_t port, int socktype)
{
	int sfd = net_socket(AF_INET6, socktype, 0);
	if (sfd == -1)
		return -1;
	struct sockaddr_in6 sockaddr;
	memset(&sockaddr, 0, sizeof(struct sockaddr_in6));
	sockaddr.sin6_family = AF_INET6;
	sockaddr.sin6_addr = in6addr_any;
	sockaddr.sin6_port = htons(port);
	if (bind(sfd, (const struct sockaddr*)&sockaddr, sizeof(sockaddr)) == -1) {
		REPORT_ERR(ENET, "bind() failed.");
		return -1;
	}
	return sfd;
}

bool net_set_timeout(int sfd, unsigned long millis)
{
#ifdef _WIN32
	DWORD tv = millis;
#else
	struct timeval tv;
	tv.tv_sec = millis / 1000;
	tv.tv_usec = (millis % 1000) * 1000;
#endif
	if (setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
		REPORT_ERR(ENET, "setsockopt() failed.");
		return false;
	}
	return true;
}

int net_udp_bind(uint16_t port)
{
	return net_bind(port, SOCK_DGRAM);
}

int net_listen(uint16_t port, int socktype)
{
	int sfd = net_bind(port, socktype);
	if (sfd == -1)
		return -1;
	if (listen(sfd, LISTEN_BACKLOG) == -1) {
		REPORT_ERR(ENET, "listen() failed.");
		return -1;
	}
	return sfd;
}

int net_accept(int socket, struct sockaddr *addr, socklen_t *addrlen)
{
	int sfd = accept(socket, addr, addrlen);
	if (sfd == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			error_clear();
			REPORT_ERR(ETIMEOUT, NULL);
		} else {
			REPORT_ERR(ENET, "accept() failed.");
		}
	}
	return sfd;
}

struct addrinfo *net_getaddrinfo(const char *node, const char *port, int family,
	int socktype)
{
	struct addrinfo hints;
	struct addrinfo *result;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = family;
	hints.ai_socktype = socktype;
	hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
	hints.ai_protocol = 0;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;
	int ret = getaddrinfo(node, port, &hints, &result);
	if (ret != 0) {
		REPORT_ERR(ENET, gai_strerror(ret));
		return NULL;
	}
	return result;
}

int net_connect(struct addrinfo info)
{
	int sfd = net_socket(info.ai_family, info.ai_socktype, info.ai_protocol);
	if (sfd == -1)
		return -1;
	if (connect(sfd, info.ai_addr, info.ai_addrlen) == -1) {
		REPORT_ERR(ENET, "connect() failed.");
		return -1;
	}
	return sfd;
}

void net_close(int socket)
{
	close(socket);
}

void net_set_nonblocking(bool noblock)
{
	nonblocking = noblock;
}

static ssize_t recvfrom_noblock(int sockfd, void *buf, size_t len)
{
	assert(buf);
	while (avail_bytes <= 0) {
		ssize_t ret = recvfrom(sockfd, recv_buffer, RECV_BUFFER_SIZE, MSG_DONTWAIT, NULL, 0);
		if (ret == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
			continue;
		if (ret == -1 || ret == 0)
			return ret;
		avail_bytes += ret;
	}
	size_t toreturn = len > avail_bytes ? avail_bytes : len;
	memcpy(buf, recv_buffer, toreturn);
	avail_bytes -= toreturn;
	if (avail_bytes > 0)
		memmove(recv_buffer, recv_buffer + toreturn, avail_bytes);
	return toreturn;
}

bool net_recv(int socket, void *buf, size_t len)
{
	assert(buf);
	size_t read = 0;
	ssize_t ret;
	while (read < len) {
		if (nonblocking)
			ret = recvfrom_noblock(socket, (char *)buf + read, len - read);
		else
			ret = recvfrom(socket, (char *)buf + read, len - read, 0, NULL, 0);
		if (ret == -1) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				REPORT_ERR(ETIMEOUT, NULL);
			} else {
				REPORT_ERR(ENET, "recvfrom() failed.");
			}
			return false;
		}
		if (ret == 0) {
			error_clear();
			REPORT_ERR(ECONNCLOSE, NULL);
			return false;
		}
		read += ret;
	}
	return true;
}

bool net_send(int socket, const void *buf, size_t len, struct addrinfo *info)
{
	assert(buf);
	size_t sent = 0;
	ssize_t ret;
	while (sent < len) {
		ret = sendto(socket, (char *)buf + sent, len - sent, 0,
			info ? info->ai_addr : NULL,
			info ? sizeof(struct sockaddr_in6) : 0);
		if (ret == -1) {
			REPORT_ERR(ENET, "send()/sendto() failed.");
			return false;
		}
		sent += ret;
	}
	return true;
}
