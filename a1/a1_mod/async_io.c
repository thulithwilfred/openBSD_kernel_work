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

#include <sys/time.h>
#include <event.h>

#include "http-parser/http_parser.h"
#include "log.h"
#include "metrics.h"
#include "async_io.h"

#define REQ_TIMEOUT 30
#define MAX_BLEN 2048

struct timeval tv;

struct req_event {
    struct event* ev;
    struct req* req;
    http_parser_settings *settings;
};

struct settings {
    struct registry *reg;
    http_parser_settings *settings;
};

http_parser_settings settings;

int reqid = 1;

static void
req_callback(int sfd, short revents, void *conn) {
    int recvd, plen;
    char * buf;
    struct req_event* req_ev = (struct req_event*)conn;
    int blen = MAX_BLEN;

    buf = malloc(sizeof(char) * blen);

    if (revents == EV_TIMEOUT) {
        printf("Timeout, closing sfd: %d\n", sfd);
        event_del(req_ev->ev);
        return;
    }

    recvd = recv(sfd, buf, blen, 0);

    if (recvd < 0) {
        tslog("error recv: %s", strerror(errno));
    } else if (recvd == 0) {
        tslog("Client disconnected");
        event_del(req_ev->ev);
        free(buf);
        return;
    }

	plen = http_parser_execute(req_ev->req->parser,
				    req_ev->settings, buf, recvd);


	if (req_ev->req->parser->upgrade) {
        /* we don't use this, so just close */
        tslog("upgrade? %d", req_ev->req->id);
        free_req(req_ev->req);
        return;
    } else if (plen != recvd) {
        tslog("http-parser gave error on %d, "
            "close", req_ev->req->id);
        free_req(req_ev->req);
        return;
	}


    printf("Recvd %d: %s", recvd, buf);
    free(buf);
}

static void
sock_event_callback(int sfd, short revents, void *conn) {
    int slen, sock;
    struct sockaddr_in raddr;
    struct event *ev;
    struct req *req;
    http_parser *parser;
    struct settings *set = (struct settings*)conn;
    struct req_event *req_ev;

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
	parser->data = req;

	req->id = reqid++;
	req->sock = sock;
	req->raddr = raddr;
	req->registry = set->reg;
	req->parser = parser;

    req->wf = fdopen(sock, "w");


	if (req->wf == NULL) {
        tslog("failed to fdopen socket: %s",
        strerror(errno));
        close(req->sock);
        free(parser);
        free(req);
        return;
	}

    ev->ev_fd = sock;
    tv.tv_sec = REQ_TIMEOUT;

    req_ev = malloc(sizeof(struct req_event));
    req_ev->ev=ev;
    req_ev->req=req;
    req_ev->settings = set->settings;

    event_set(ev, EVENT_FD(ev), EV_READ | EV_PERSIST, req_callback, req_ev);
    event_add(ev, &tv);

    printf("Client accepted on fd %d...\n", sock); 
}

void
async_init(int lsock, struct registry *registry, http_parser_settings *http_settings) {
        struct event *ev = malloc(sizeof(struct event));
        struct settings *set = malloc(sizeof(struct settings));

        set->reg = registry;
        set->settings = http_settings; //wtf is this

        ev->ev_fd = lsock;
        printf("Setting Up Async IO on %d\n", lsock);
        event_init();
        event_set(ev, EVENT_FD(ev), EV_READ | EV_PERSIST, sock_event_callback, set);
        event_add(ev, NULL);
        event_dispatch();   //Start event loop   
}