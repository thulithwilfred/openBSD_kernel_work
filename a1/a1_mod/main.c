/*
 *
 * Copyright 2020 The University of Queensland
 * Author: Alex Wilson <alex@uq.edu.au>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/cdefs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <err.h>

#include <event.h>

#include "http-parser/http_parser.h"
#include "log.h"
#include "metrics.h"

#include <event.h>
#include "async_io.h"

const int BACKLOG = 8;
const size_t BUFLEN = 2048;


/* Global list of all open reqs */
static struct req *reqs = NULL;

static int on_url(http_parser *, const char *, size_t);
static int on_header_field(http_parser *, const char *, size_t);
static int on_header_value(http_parser *, const char *, size_t);
static int on_body(http_parser *, const char *, size_t);
static int on_headers_complete(http_parser *);
static int on_message_complete(http_parser *);

static char *stats_buf = NULL;
static size_t stats_buf_sz = 0;

void
free_req(struct req *req)
{
	/* Remove this req from the reqs list */
	if (req->prev == NULL)
		reqs = req->next;
	if (req->prev != NULL)
		req->prev->next = req->next;
	if (req->next != NULL)
		req->next->prev = req->prev;

	/*
	 * Close the accepted client socked fd.
	 */
	close(req->sock);

	free(req->parser);
	free(req);
}

static __dead void
usage(const char *arg0)
{
	fprintf(stderr, "usage: %s [-f] [-l logfile] [-p port]\n", arg0);
	fprintf(stderr, "listens for prometheus http requests\n");
	exit(EXIT_USAGE);
}

extern FILE *logfile;

int
main(int argc, char *argv[])
{
	const char *optstring = "p:fl:";
	uint16_t port = 27600;
	int daemon = 1;

	int lsock;
	struct sockaddr_in laddr;
	http_parser_settings settings;
	struct registry *registry;
	int c;
	unsigned long int parsed;
	char *p;
	pid_t kid;

	logfile = stdout;

	/*
	 * Set up the timezone information for localtime() et al. This is used
	 * by the tslog() routines in log.c to print timestamps in local time.
	 */
	tzset();

	/* Parse our commandline arguments. */
	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'p':
			errno = 0;
			parsed = strtoul(optarg, &p, 0);
			/*
			 * If strtoul() fails, it sets errno. If there's left
			 * over characters other than a number, though, it
			 * doesn't set errno. Check if it advanced "p" all the
			 * way to the end.
			 */
			if (errno != 0 || *p != '\0') {
				errx(EXIT_USAGE, "invalid argument for "
				    "-p: '%s'", optarg);
			}
			/* Ports have to fit in a uint16_t */
			if (parsed >= UINT16_MAX) {
				errx(EXIT_USAGE, "invalid argument for "
				    "-p: '%s' (too high)", optarg);
			}
			port = parsed;
			break;
		case 'f':
			daemon = 0;
			break;
		case 'l':
			logfile = fopen(optarg, "a");
			if (logfile == NULL)
				err(EXIT_USAGE, "open('%s')", optarg);
			break;
		default:
			usage(argv[0]);
		}
	}

	if (daemon) {
		kid = fork();
		if (kid < 0) {
			err(EXIT_ERROR, "fork");
		} else if (kid > 0) {
			/* The parent process exits immediately. */
			return (0);
		}
		umask(0);
		if (setsid() < 0)
			tserr(EXIT_ERROR, "setsid");
		chdir("/");

		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}

	/* Initialise the collector module registry */
	registry = registry_build();

	/*
	 * Set up our "settings" struct for http_parser, which contains the
	 * callbacks that will run when the parser encounters different parts
	 * of the HTTP request.
	 */
	bzero(&settings, sizeof(settings));
	settings.on_headers_complete = on_headers_complete;
	settings.on_message_complete = on_message_complete;
	settings.on_url = on_url;
	settings.on_body = on_body;
	settings.on_header_field = on_header_field;
	settings.on_header_value = on_header_value;

	/*
	 * Ignore SIGPIPE if we get it from any of our sockets: we'll poll
	 * them for read/hup/err later and figure it out anyway.
	 */
	signal(SIGPIPE, SIG_IGN);

	/* Now open our listening socket */

	lsock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
	if (lsock < 0)
		tserr(EXIT_SOCKERR, "socket()");

	if (setsockopt(lsock, SOL_SOCKET, SO_REUSEADDR,
	    &(int){ 1 }, sizeof(int))) {
		tserr(EXIT_SOCKERR, "setsockopt(SO_REUSEADDR)");
	}

	bzero(&laddr, sizeof(laddr));
	laddr.sin_family = AF_INET;			/* XXX: ipv6? */
	laddr.sin_port = htons(port);

	if (bind(lsock, (struct sockaddr *)&laddr, sizeof(laddr)))
		tserr(EXIT_SOCKERR, "bind(%d)", port);

	if (listen(lsock, BACKLOG))
		tserr(EXIT_SOCKERR, "listen(%d)", port);

	tslog("listening on port %d", port);

	/* And begin handling requests! */
	async_init(lsock, registry, &settings);

	registry_free(registry);

	return (0);
}

static int
on_url(http_parser *parser, const char *url, size_t ulen)
{
	struct req *req = parser->data;
	if (parser->method == HTTP_GET &&
	    ulen >= strlen("/metrics") &&
	    strncmp(url, "/metrics", strlen("/metrics")) == 0) {
		req->resp = RESP_METRICS;
	}
        if (parser->method == HTTP_GET &&
            ulen >= strlen("/stopme") &&
            strncmp(url, "/stopme", strlen("/stopme")) == 0) {
		exit(0);
        }
	return (0);
}

static int
on_body(http_parser *parser, const char *data, size_t len)
{
	//struct req *req = parser->data;
	return (0);
}

static int
on_header_field(http_parser *parser, const char *hdrname, size_t hlen)
{
	//struct req *req = parser->data;
	return (0);
}

static int
on_header_value(http_parser *parser, const char *hdrval, size_t vlen)
{
	//struct req *req = parser->data;
	return (0);
}

static int
on_headers_complete(http_parser *parser)
{
	//struct req *req = parser->data;
	return (0);
}

static void
send_err(http_parser *parser, enum http_status status)
{
	struct req *req = parser->data;
	/* Modified to achieve async IO */
	struct event *ev;
	struct req_write *req_wr;
	char* output_buffer;
	int output_buffer_size;

	ev = malloc(sizeof(struct event));
	req_wr = malloc(sizeof(struct req_write));

	/* Create complete output buffer */
	output_buffer = NULL;
	output_buffer_size  = asprintf(&output_buffer, 
		"HTTP/%d.%d %d %s\r\n"
		"Server: obsd-prom-exporter\r\n"
		"Connection: close\r\n"
		"\r\n", parser->http_major,
	    parser->http_minor, status, http_status_str(status));

#ifdef DEBUG_MODE
	printf("Output Buffer Size: %d\n\n %s", output_buffer_size , output_buffer);
#endif

	ev->ev_fd = req->sock;

	req_wr->ev = ev;
	req_wr->write_buffer = output_buffer;
	req_wr->write_len = output_buffer_size;
	req_wr->partial_write_len = 0;
	req_wr->req = req;

	/* Add write to call async IO callback
	 * Memory clean up is done by the callbacks.
	 */
	add_write_callback(req_wr);		
}

static int
on_message_complete(http_parser *parser)
{
	struct req *req = parser->data;
	FILE *mf;
	off_t off;
	int r;
	char* output_buffer;
	int output_buffer_size;

	/* If we didn't recognise the method+URL, return a 404. */
	if (req->resp == RESP_NOT_FOUND) {
		send_err(parser, 404);
		return (0);
	}

	if (stats_buf == NULL) {
		stats_buf_sz = 256*1024;
		stats_buf = malloc(stats_buf_sz);
	}
	if (stats_buf == NULL) {
		tslog("failed to allocate metrics buffer");
		send_err(parser, 500);
		return (0);
	}
	mf = fmemopen(stats_buf, stats_buf_sz, "w");
	if (mf == NULL) {
		tslog("fmemopen failed: %s", strerror(errno));
		send_err(parser, 500);
		return (0);
	}

	tslog("generating metrics for req %d...", req->id);
	r = registry_collect(req->registry);
	if (r != 0) {
		tslog("metric collection failed: %s", strerror(r));
		send_err(parser, 500);
		return (0);
	}
	print_registry(mf, req->registry);
	fflush(mf);
	off = ftell(mf);
	if (off < 0) {
		send_err(parser, 500);
		return (0);
	}
	fclose(mf);
	tslog("%d done, sending %lld bytes", req->id, off);

	/* Modified to achieve async IO */
	struct event *ev;
	struct req_write *req_wr;

	ev = malloc(sizeof(struct event));
	req_wr = malloc(sizeof(struct req_write));

	/* Prometheus expects this version=0.0.4 in the content-type to
	 * indicate that it's the prometheus text format.
	 */

	/* Create complete output buffer */
	output_buffer = NULL;
	output_buffer_size = asprintf(&output_buffer,"HTTP/%d.%d %d %s\r\n"
				"Server: obsd-prom-exporter\r\n"
				"Content-Type: "
				    "text/plain; version=0.0.4; charset=utf-8\r\n"
				"Content-Length: %lld\r\n"
				"Connection: close\r\n"
				"\r\n"
				 "%s", parser->http_major, parser->http_minor, 200, http_status_str(200),
				 off, stats_buf			 
				 );

#ifdef DEBUG_MODE
	printf("Output Buffer Size: %d\n\n %s", output_buffer_size, output_buffer);
#endif
	ev->ev_fd = req->sock;

	req_wr->ev = ev;
	req_wr->write_buffer = output_buffer;
	req_wr->write_len = output_buffer_size;
	req_wr->partial_write_len = 0;
	req_wr->req = req;
	
	/* Add write to call async IO callback
	 * Memory clean up is done by the callbacks.
	 */
	add_write_callback(req_wr);

	return (0);
}




