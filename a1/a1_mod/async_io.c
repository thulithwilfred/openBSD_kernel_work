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
#include <stdbool.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/cdefs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <err.h>

#include <sys/time.h>
#include <event.h>

#include "http-parser/http_parser.h"
#include "log.h"
#include "metrics.h"
#include "async_io.h"

//#define DEBUG_MODE

#define REQ_TIMEOUT 30
#define MAX_BLEN 2048

/* Event timeout Struct */
struct timeval tv;

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

/* Holds registry and parser settings,
 * used for event callbacks 
 */
struct settings {
    struct registry *reg;
    http_parser_settings *settings;
};

http_parser_settings settings;

/* Current request ID */
int reqid = 1;

/**
 * @brief Cleanup function for requests.
 *        Will free the allocated memory for a buffer, and the associated request.
 * @note  See free_req() in main.c for additional information.  
 * 
 * @param req_ev request event structure associated with the wiping request. 
 */
void wipe_request(struct req_event* req_ev) {
    /* Clear recv buffer */
    free(req_ev->recv_buffer);
    /* Clear read events */
    event_del(req_ev->ev);
    /* Clear reqeust packet */
    free_req(req_ev->req);
    /* Clear request event  data */
    free(req_ev);
}

/**
 * @brief Cleans up both write and read associated reqeust data.
 * 			must be called only when a request is completed either by 
 *			succesful parsing or invalid request. 

 * @note Wipe request is also called by invalid receives. 
 * @param req_wr write request data struct. 
 */
void clean_up_write(struct req_write *req_wr) {
	/* Clear any read event associated data */
	wipe_request(req_wr->req->req_ev);
	/* Clear write events */
	event_del(req_wr->ev);
	/* Clear write buffer */
	free(req_wr->write_buffer);
	/* Clear write ev struct */
	free(req_wr->ev);
	/* Clear req_wr data */
	free(req_wr);
}


/**
 * @brief Adds write request to the even loop, 
			receives a call back when the FD can be written to. 
 * 
 * @param req_wr 
 */
void
add_write_callback(struct req_write *req_wr) {
	event_set(req_wr->ev, EVENT_FD(req_wr->ev), EV_WRITE | EV_PERSIST, sock_write_event_callback, req_wr);
	event_add(req_wr->ev, NULL);
}



/**
 * @brief Test to see if the input buffer contain either a sequence of
            "\n\n" or "\n\r\n\r" to indicate the end of a http request. 
 * 
 * @param buffer http request to test for completion
 * @param len lenght of buffer
 * @return true if either sequence is detected at the end
 * @return false if sequence is not detected
 */
static bool end_of_req(char* buffer, int len) {
    //printf("DD %d %d %d %d\n", buffer[len - 1], buffer[len - 2], buffer[len - 3] ,buffer[len - 4]);
    if (buffer[len - 1] == '\n' && buffer[len - 2] == '\r' && buffer[len - 3] == '\n' && buffer[len - 4] == '\r') {
        /* \n\r\n\r */
        return true;
    } else if (buffer[len - 1] == '\n' && buffer[len - 2] == '\n') {
        /* \n\n */
        return true;
    }
    return false;
}


void
sock_write_event_callback(int sfd, short revents, void *conn) {
	struct req_write *req_wr;
	int sent;

	req_wr = (struct req_write *)conn;
	/* Sent as much data as we can, socket is opened in non-blocking 
	 * partial_write_len is initially 0, and will increment the send buffer as required. 
	 */
	
	sent = send(req_wr->req->sock, req_wr->write_buffer + req_wr->partial_write_len,req_wr->write_len - req_wr->partial_write_len, MSG_DONTWAIT);

	if (sent == EAGAIN) {
		/* Shoudn't really get here, since event based */
		return;
	}

	if (sent < 0) {
		warnx("Send error to ReqID: %d, closing...\n", req_wr->req->id);
		clean_up_write(req_wr);
	}

	if (sent == req_wr->write_len) {
		tslog("Write Complete to ReqID %d, cleaning up...", req_wr->req->id);
		req_wr->req->done = 1;
		clean_up_write(req_wr);
		return;
	}
	req_wr->partial_write_len += sent;
}



/**
 * @brief Handles client events caused on the respective file descriptor.
 * 			
 * @param sfd Client file descriptor  
 * @param revents Event callback flags
 * @param conn Request data, struct
 */
static void
req_callback(int sfd, short revents, void *conn) {
    int recvd, plen;
    struct req_event* req_ev = (struct req_event*)conn;
    int blen = MAX_BLEN;
    int recv_len = req_ev->recv_len;

    if (revents == EV_TIMEOUT) {
        tslog("Timeout for ReqID: %d, closing...", req_ev->req->id);
        wipe_request(req_ev);
        return;
    }

    /*
     * Receive data as long as it fits into the remaining of MAX_BLEN, then append to the end of the current
     * request buffer. This allows for partial requests to be appended onto. 
     */
    recvd = recv(sfd, req_ev->recv_buffer + recv_len, blen - recv_len, 
MSG_DONTWAIT);
    req_ev->recv_len += recvd;   

    if (recvd == EAGAIN) {
		/* Shoudn't really get here, since event based */
		return;
	}

    if (recvd < 0) {
        tslog("Error recv: %s", strerror(errno));
        wipe_request(req_ev);
        return;
    } else if (recvd == 0) {
        warnx("Client on ReqID: %d disconnected...", req_ev->req->id);
        wipe_request(req_ev);
        return;
    }

#ifdef DEBUG_MODE
    printf("Incoming Request:\n\r%s", req_ev->recv_buffer + recv_len);
#endif

    /* Check to see if the current state of the request is complete */
    if (end_of_req(req_ev->recv_buffer, req_ev->recv_len) == false) {
        tslog("Partial Requst Received...waiting for %d to complete", req_ev->req->id);
        return;
    }
    
    plen = http_parser_execute(req_ev->req->parser,
                req_ev->settings, req_ev->recv_buffer, req_ev->recv_len);

	if (req_ev->req->parser->upgrade) {
        /* we don't use this, so just close */
        tslog("Upgrade? %d", req_ev->req->id);
        wipe_request(req_ev);
        return;
    } else if (plen != req_ev->recv_len) {
        tslog("http-parser gave error on ReqID %d, "
            "closing...", req_ev->req->id);
        /* Request could be invalid or incomplete */
        wipe_request(req_ev);
        return;
	}
}


/**
 * @brief Sets up event handlers for incomming connections on the socket file descriptors.
 *			and adds accepted client file descripters to events list. 
 * 
 * @param sfd Socket file descriptor
 * @param revents Event callback flags
 * @param conn Settings data 
 */
static void
sock_event_callback(int sfd, short revents, void *conn) {
    struct sockaddr_in raddr;
    struct event *ev;
    struct req *req;
    http_parser *parser;
    struct settings *set = (struct settings*)conn;
    struct req_event *req_ev;
    int slen, sock;
    int blen = MAX_BLEN;

    /* Accept incoming connections */
    slen = sizeof(raddr);
    sock = accept4(sfd, (struct sockaddr *)&raddr, &slen, SOCK_NONBLOCK);

    tslog("accepted connection from %s (req %d)",
        inet_ntoa(raddr.sin_addr), reqid);

    if (sock < 0) {
		switch (errno) {
		case ECONNABORTED:
		case ECONNRESET:
			tslog("failed to accept connection "
			    "from %s: %d (%s)",
			    inet_ntoa(raddr.sin_addr),
			    errno, strerror(errno));
				break;
			default:
				tserr(EXIT_SOCKERR, "accept()");
	    }
    }

    ev = malloc(sizeof(struct event));
	req = calloc(1, sizeof(struct req)); 

    if (req == NULL) {
        tserr(EXIT_MEMORY, "calloc(%zd)",
            sizeof(struct req));
	}
	parser = calloc(1, sizeof(http_parser));
	if (parser == NULL) {
        tserr(EXIT_MEMORY, "calloc(%zd)",
        sizeof(http_parser));
	}

	http_parser_init(parser, HTTP_REQUEST);
    /* Setup request and parser data*/
	parser->data = req;

	req->id = reqid++;
	req->sock = sock;
	req->raddr = raddr;
	req->registry = set->reg;
	req->parser = parser;

    ev->ev_fd = sock;
    tv.tv_sec = REQ_TIMEOUT;

    /* 
     * Setup all required data for an incoming request,
     * if a request is completed or dropped, these are to be freed. 
     */
    req_ev = malloc(sizeof(struct req_event));
    req->req_ev=req_ev;
    req_ev->ev=ev;
    req_ev->req=req;
    req_ev->settings = set->settings;
    req_ev->recv_buffer = malloc(sizeof(char) * blen);
    req_ev->recv_len = 0;
    
    event_set(ev, EVENT_FD(ev), EV_READ | EV_PERSIST, req_callback, req_ev);
    event_add(ev, &tv);
}

/**
 * @brief Initialise async I/O using lib event, sets up the event loop.
 * @note Funtion only returns when the event loops exits or returns error
 *
 * @param lsock socket fd
 * @param registry registry settings
 * @param http_settings http parser settings
 */
void
async_init(int lsock, struct registry *registry, http_parser_settings *http_settings) {
	int ev_err;
    struct event *ev = malloc(sizeof(struct event));
    struct settings *set = malloc(sizeof(struct settings));

    set->reg = registry;
    set->settings = http_settings; 

    ev->ev_fd = lsock;
    tslog("Setting Up Async IO on sfd%d\n", lsock);
    event_init();
    event_set(ev, EVENT_FD(ev), EV_READ | EV_PERSIST, sock_event_callback, set);
    event_add(ev, NULL);

    /* Begin event loop */
    ev_err = event_dispatch();     

    if (ev_err < 0) {
        /* Should not get here */
		tslog("Error on event loop\n");
    }

    free(set);
	free(ev);
}