#ifdef HAVE_CONFIG_H
#include <config.h>
#else
#define PACKAGE_STRING "connect-4 1.0.0"
#endif /* HAVE_CONFIG_H */

#include <arpa/inet.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "client/cin.h"
#include "client/connect4.h"
#include "cout.h"
#include "stringop.h"

#define USAGE_STRING	\
	"Usage: %s [-h] [-v] [-i <num>] [-H <host>] [-p <port>] [-l <port>]"

/*
 * Prints an error and exits with EXIT_FAILURE. If errno is non-zero,
 * the function appends a description of the error code to the message.
 */
static void panic(const char *errstr, int errno)
{
	cout_print_error(errstr, errno);
	exit(EXIT_FAILURE);
}

/* Formats and prints an error, then it exits with EXIT_FAILURE. */
static void panicf(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	cout_vprintf_error(format, args);
	exit(EXIT_FAILURE);
}

/* Prints help message and exits. */
static inline void print_help(const char *cmdname)
{
	printf(USAGE_STRING "\n\n"
		"-h:\tprints this message and exits\n"
		"-v:\tprints version infos and exits\n"
		"-i:\tforce a specific IP protocol version (4 or 6)\n"
		"-H:\tspecifies the server hostname/address\n"
		"-p:\tspecifies the server port\n"
		"-l:\tspecifies the p2p listening port\n",
		cmdname);
	exit(EXIT_SUCCESS);
}

/* Prints package name and version, then it exits. */
static inline void print_version()
{
	puts(PACKAGE_STRING " (client)");
	exit(EXIT_SUCCESS);
}

/* Client entry-point. */
int main(int argc, char **argv)
{
	uint16_t server_port = 55555;
	uint16_t listening_port = 50505;
	char server_addr[254] = "";
	int force_ipv = 0;
	int opt;

	while ((opt = getopt(argc, argv, "+:hvi:H:p:l:")) != -1)
		switch (opt) {
		case 'h':
			print_help(argv[0]);
		case 'v':
			print_version();
		case 'i':
			if (!string_to_int(optarg, &force_ipv)
					|| (force_ipv != 4 && force_ipv != 6))
				panicf("Invalid option argument for -i: %s.",
					optarg);
			break;
		case 'H':
			strncpy(server_addr, optarg, 254);
			if (server_addr[253] != '\0')
				panic("Server address is too long.", 0);
			break;
		case 'p':
			if (!string_to_uint16(optarg, &server_port))
				panicf("Invalid port number %s. Enter a value between 0 and 65535.",
					optarg);
			break;
		case 'l':
			if (!string_to_uint16(optarg, &listening_port))
				panicf("Invalid port number %s. Enter a value between 0 and 65535.",
					optarg);
			break;
		default:
			panicf("Invalid option: %c.\n" USAGE_STRING,
				optopt, argv[0]);
		}

	if (optind < argc)
		panicf("Invalid argument: %s.\n" USAGE_STRING,
			argv[optind], argv[0]);

	printf("force_ipv = %d\n"
		"server_addr = %s\n"
		"server_port = %hu\n"
		"listening_port = %hu\n",
		force_ipv, server_addr, server_port, listening_port);

	return 0;
}
