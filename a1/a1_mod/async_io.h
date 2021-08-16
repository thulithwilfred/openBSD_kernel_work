#ifndef ASYNC_IO_H
#define ASYNC_IO_H

enum response_type {
	RESP_NOT_FOUND = 0,
	RESP_METRICS
};


/*
 * Struct representing a request that's being processed and the connection it's
 * being received on (each connection can send only one request at present, so
 * these are the same).
 */
struct req {
	int id;				/* A serial number for this req */
	int done;			/* Is the request done? 1 = true */

	/* Links for the "reqs" list */
	struct req *next;
	struct req *prev;

	struct registry *registry;	/* The metrics registry */

	struct sockaddr_in raddr;	/* Remote peer */
	size_t pfdnum;			/* pollfd index, or 0 if not polled */
	int sock;			/* Client socket */
	FILE *wf;			/* Writable FILE of our client socket */

	struct http_parser *parser;
	enum response_type resp;	/* Response type based on URL+method */
};


void async_init(int lsock, struct registry *registry, http_parser_settings *http_settings);

void free_req(struct req *req);

#endif