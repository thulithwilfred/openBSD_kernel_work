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

	struct req_event *req_ev;

	struct sockaddr_in raddr;	/* Remote peer */
	size_t pfdnum;			/* pollfd index, or 0 if not polled */
	int sock;			/* Client socket */

	struct http_parser *parser;
	enum response_type resp;	/* Response type based on URL+method */
};


struct req_write {
	struct event* ev;
	struct req* req;
	char* write_buffer;
	int write_len; /* Buffer lenght */
	int partial_write_len; /* How much was written */
};


void async_init(int , struct registry *, http_parser_settings *);

void free_req(struct req *);

void add_write_callback(struct req_write *req_wr);

void clean_up_write(struct req_write *req_wr);

void wipe_request(struct req_event* req_ev);

void sock_write_event_callback(int sfd, short revents, void *conn);

#endif