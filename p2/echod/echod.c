#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <netdb.h>
#include <errno.h>
#include <err.h>

#include <event.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <sys/queue.h>

/*
 * maybe useful functions. they're not static so the linker doesnt get upset.
 */
void	hexdump(const void *, size_t);
void	msginfo(const struct sockaddr_storage *, socklen_t, size_t);

__dead static void usage(void);

struct echod {
	TAILQ_ENTRY(echod)
			entry;
	struct event	ev;
};
TAILQ_HEAD(echod_list, echod);

#define RECV_BUFF_SIZE 256

static void
echod_recv(int sfd, short revents, void *conn)
{
	struct sockaddr_storage peer_addr; //Hold peer address
    socklen_t peer_addr_len; //Peer addr len

	char* recvBuffer = malloc(sizeof(char) * RECV_BUFF_SIZE);
	int nread = recvfrom(sfd, recvBuffer, RECV_BUFF_SIZE, 0, (struct sockaddr *) &peer_addr, &peer_addr_len);
	

	if (nread == -1) {
		warnx("Error in revcfrom call");
	}

	printf("ECHO_BACK: %s", recvBuffer);

	int nwrite = sendto(sfd, recvBuffer, nread, 0, (struct sockaddr *) &peer_addr,
                           peer_addr_len);

	if (nwrite != nread) {
		warnx("Error sending echo reponse");
	}

	free(recvBuffer);
}

__dead static void
usage(void)
{
	extern char *__progname;
	fprintf(stderr, "usage: %s [-46] [-l address] [-p port]\n", __progname);
	exit(1);
}

static void
echod_bind(struct echod_list *echods, sa_family_t af,
    const char *host, const char *port)
{
	int serrno = ENOTCONN;
	const char *cause = "missing code";

    struct addrinfo hints;
	struct addrinfo *result;
	int err, sfd;

	memset(&hints, 0, sizeof(hints));
	/* Set AI Hints */
	hints.ai_family = af;    			/* IPvX*/
    hints.ai_socktype = SOCK_DGRAM; 	/* Datagram socket */
    hints.ai_flags = AI_PASSIVE;    	/* For wildcard IP address */
    hints.ai_protocol = 0;          	/* Any protocol */
    hints.ai_canonname = NULL;
    hints.ai_addr = NULL;
    hints.ai_next = NULL;

	err = getaddrinfo(host, port, &hints, &result);

	if (err != 0) {
		errx(-1, "getaddrinfo: %s\n", gai_strerror(err));
	}

	/* Attemp to bind */
	sfd = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	
	if (sfd == -1) {
		errx(-1, "Unable to create socket");
	} 
	/* Bind to socket */
	if(bind(sfd, result->ai_addr, result->ai_addrlen) == 0) {
		printf("Bind complete\n");
		freeaddrinfo(result);
	}

	/* Setup echod struct, update SFD and post to TAILQ */
	struct echod *echoPacket = malloc(sizeof(struct echod) * 1);
	memset(echoPacket, 0, sizeof(*echoPacket));
	echoPacket->ev.ev_fd = sfd;

	TAILQ_INSERT_HEAD(echods, echoPacket, entry);

	if (TAILQ_EMPTY(echods))
		errc(1, serrno, "host %s port %s %s", host, port, cause);
}

int
main(int argc, char *argv[])
{
	struct echod *e;
	struct echod_list echods = TAILQ_HEAD_INITIALIZER(echods);
	sa_family_t af = AF_INET;
	const char *host = "localhost";
	const char *port = "3301";
	int ch;

	while ((ch = getopt(argc, argv, "46l:p:")) != -1) {
		switch (ch) {
		case '4':
			af = AF_INET;
			break;
		case '6':
			af = AF_INET6;
			break;

		case 'l':
			host = (strcmp(optarg, "*") == 0) ? NULL : optarg;
			break;
		case 'p':
			port = optarg;
			break;
		default:
			usage();
			/* NOTREACHED */
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();

	warnx("\n\r  Connecting on: %s \n\r  Port: %s \n\r  AF: %s \n\r", host, port, (af == AF_INET ? "IPv4":"IPv6"));

	echod_bind(&echods, af, host, port); /* this works or exits */

	event_init();

	TAILQ_FOREACH(e, &echods, entry) {
		event_set(&e->ev, EVENT_FD(&e->ev), EV_READ|EV_PERSIST,
		    echod_recv, e);
		event_add(&e->ev, NULL);
	}

	event_dispatch();

	return (0);
}

/*
 * possibly useful functions
 */
void
hexdump(const void *d, size_t datalen)
{
	const uint8_t *data = d;
	size_t i, j = 0;

	for (i = 0; i < datalen; i += j) {
		printf("%4zu: ", i);
		for (j = 0; j < 16 && i+j < datalen; j++)
			printf("%02x ", data[i + j]);
		while (j++ < 16)
			printf("   ");
		printf("|");
		for (j = 0; j < 16 && i+j < datalen; j++)
			putchar(isprint(data[i + j]) ? data[i + j] : '.');
		printf("|\n");
	}
}

void
msginfo(const struct sockaddr_storage *ss, socklen_t sslen, size_t len)
{
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	int error;

	error = getnameinfo((const struct sockaddr *)ss, sslen,
	    hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
	    NI_NUMERICHOST | NI_NUMERICSERV);
	if (error != 0) {
		warnx("msginfo: %s", gai_strerror(error));
		return;
	}

	printf("host %s port %s bytes %zu\n", hbuf, sbuf, len);
}
