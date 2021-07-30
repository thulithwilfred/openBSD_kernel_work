/* 
** CSSE2310/7231 - sample client - code to be commented in class
** Send a request for the top level web page (/) on some webserver and
** print out the response - including HTTP headers.
** 
** Name: Wilfred Mallawa
** SID : s4428042
*/
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h> 
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include "usage.h"

#define CONNECTION_PORT 80


void
send_HTTP_request(int fd, char* file, char* host)
{
    char* requestString;

    /* Allocate enough space for our HTTP request */
    //requestString = (char*)malloc(strlen(file) + strlen(host) + 26);

    /* Construct HTTP request:
     * GET / HTTP/1.0
     * Host: hostname
     * <blank line>
     */
    //sprintf(requestString, "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", file, host);

    /* 
     *Memory is dynamically allocated by asprintf based on request size  [PRAC 1]
     */
    asprintf(&requestString, "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", file, host);
  
    /* Send our request to server */
    if(write(fd, requestString, strlen(requestString)) < 1) {
        free(requestString);
	    errx(1, "%s", "Write error");
    }

    free(requestString);
}

void
get_and_output_HTTP_response(int fd)
{
    char buffer[1024];
    int numBytesRead;
    int eof = 0;

    // Repeatedly read from network fd until nothing left - write 
    // everything out to stdout
    while(!eof) {
	    numBytesRead = read(fd, buffer, 1024);
	    if(numBytesRead < 0) {
            errx(1, "%s", "Read Error");
	    } else if(numBytesRead == 0) {
	        eof = 1;
	    } else {
	        fwrite(buffer, sizeof(char), numBytesRead, stdout);
	    }
    }
}

/**
 * @brief Resolves IP from host name and attempts to connect 
            to this IP addr. If connection is established,
            the respective socket file discriptor is returned.
 * 
 * @param hostname hostname to connect to
 * @return int socket fd
 */
int 
resolve_and_connect(struct userArgs *connectionArgs) {
    int error, sfd, save_errno;
    struct addrinfo* addressInfo, *res, hints;
    const char *cause = NULL;

    char* hostname = connectionArgs->hostname;
    int port = connectionArgs->port;
    int ai_family = connectionArgs->ai_family;

    /* Hints to point getaddr in the right direction */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = connectionArgs->ai_family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    warnx("\n\r\r Port: %d\n\r\r Hostname: %s\n\r\r IPV: %s\n\r\r", port, hostname, ((ai_family == AF_INET) ? "IPV4":"IPV6"));

    error = getaddrinfo(hostname, NULL, &hints, &addressInfo);

    if(error) 
	    usage(BADHOST);
    
    sfd = -1; 

    for (res = addressInfo; res; res = res->ai_next) {
        sfd = socket(res->ai_family, res->ai_socktype,
	            res->ai_protocol);

	    if (sfd == -1) {
		    cause = "socket";
		    continue;
        }

        switch(res->ai_family) {
            case AF_INET:
                ((struct sockaddr_in *)(res->ai_addr))->sin_port = htons(connectionArgs->port);
                break;
            case AF_INET6:
                ((struct sockaddr_in6 *)(res->ai_addr))->sin6_port = htons(connectionArgs->port);
                break;
        }

        if (connect(sfd, res->ai_addr, res->ai_addrlen) == -1) {
		    cause = "connect";
		    save_errno = errno;
		    close(sfd);
		    errno = save_errno;
		    sfd = -1;
		    continue;
	    }
        break;	/* okay we got one */
    }

    if (sfd == -1)
        err(1, "%s", cause);

    freeaddrinfo(addressInfo); //Connected, no, longer required
    return sfd;
}

/**
 * @brief Simple program that sends and reads HTTPS request,
            the user can tell which host to connect to and on which port
            /which ipv protocol (IPv4/6.
 * 
 * @param argc arg count
 * @param argv args
 * @return int 0 on success
 */
int
main(int argc, char* argv[]) {
    int  ch, fd;
    struct userArgs connectionArgs;

    if(argc < 2) {
        /*
         * Usage function is non-returning
         */
	    usage(BADARGS);
    }

    /*
     * Set defaults
     */
    connectionArgs.port = CONNECTION_PORT;
    connectionArgs.ai_family = AF_INET; 
    connectionArgs.hostname = "";

    while(optind < argc) {
        if ((ch = getopt(argc, argv, "?46p:")) != -1) {
            switch (ch) {
                case 'p':
                    connectionArgs.port = atoi(optarg);
                    break;
               case '4':
                   connectionArgs.ai_family = AF_INET;
                    break;
                case '6':
                    connectionArgs.ai_family = AF_INET6;
                    break;
               case '?':
                 usage(HELP);
                 break;
             default:
                 break;
            }
        } else {
            connectionArgs.hostname = argv[optind];
            optind++;
        }
    }

     /* 
      * PRAC1: Merge `name_to_IP_addr()` and `connect_to()`
      */
     fd = resolve_and_connect(&connectionArgs);
     send_HTTP_request(fd, "/", connectionArgs.hostname);
     get_and_output_HTTP_response(fd);
     close(fd);

    return 0;
}
