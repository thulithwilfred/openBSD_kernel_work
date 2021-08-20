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

	struct registry *registry;	/* The metrics registry */

	struct req_event *req_ev;

	struct sockaddr_in raddr;	/* Remote peer */
	size_t pfdnum;			/* pollfd index, or 0 if not polled */
	int sock;			/* Client socket */

	struct http_parser *parser;
	enum response_type resp;	/* Response type based on URL+method */
};


struct req_write {
	struct event *ev;
	struct req *req;
	char* write_buffer;
	int write_len; /* Buffer length */
	int partial_write_len; /* Bytes written last time */
};

/* Holds registry and parser settings,
 * used for event callbacks 
 */
struct settings {
    struct registry *reg;
    http_parser_settings *settings;
};

/* Holds request data, parser settings and event 
 * struct pointers, used for event callbacks 
 */
struct req_event {
    struct event* ev;
    struct req* req;
    char* recv_buffer; 
    int recv_len;
    http_parser_settings *settings;
};

void async_init(int , struct registry *, http_parser_settings *);

void free_req(struct req *);

void add_write_callback(struct req_write *req_wr);

void clean_up_write(struct req_write *req_wr);

void wipe_request(struct req_event* req_ev);

void sock_write_event_callback(int sfd, short revents, void *conn);

#endif