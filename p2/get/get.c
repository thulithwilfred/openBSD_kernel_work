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
#include "usage.h"

#define CONNECTION_PORT 80

void
send_HTTP_request(int fd, char* file, char* host)
{
    char* requestString;

    /* Allocate enough space for our HTTP request */
    requestString = (char*)malloc(strlen(file) + strlen(host) + 26);

    /* Construct HTTP request:
     * GET / HTTP/1.0
     * Host: hostname
     * <blank line>
     */
    sprintf(requestString, "GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", file, host);

    /* Send our request to server */
    if(write(fd, requestString, strlen(requestString)) < 1) {
	    perror("Write error");
	    exit(1);
    }
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
	    perror("Read error\n");
	    exit(1);
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
resolve_and_connect(char* hostname) {
    int error, fd;
    struct addrinfo* addressInfo;
    struct sockaddr_in socketAddr;
    struct in_addr ipAddress;

    error = getaddrinfo(hostname, NULL, NULL, &addressInfo);

    if(error) {
	    usage(BADHOST);
    }

    /*
     * Extract IP Addr
     */
    ipAddress = (((struct sockaddr_in*)(addressInfo->ai_addr))->sin_addr);


    /*
     * Create a structure that represents the IP address and port number
     * that we're connecting to.
     */
    socketAddr.sin_family = AF_INET;	/* IP v4 */
    socketAddr.sin_port = htons(CONNECTION_PORT);	/* Convert port number to network byte order */
    socketAddr.sin_addr.s_addr = ipAddress.s_addr;	/* Copy IP address - already in network byte order */

    
    /* 
     * Create TCP socket 
     */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0) {
	    perror("Error creating socket");
	    exit(EXIT_SOCKETERR);
    }

    /*
     * Attempt to connect to server at that address 
     */
    if(connect(fd, (struct sockaddr*)&socketAddr, sizeof(socketAddr)) < 0) {
	    perror("Error connecting");
	    exit(EXIT_CONNECT);
    }

    freeaddrinfo(addressInfo); //Connected, no, longer required
    return fd;
}


int
main(int argc, char* argv[]) {
    int fd;
    char* hostname;

    if(argc != 2) {
        /*
         * Usage function is non-returning
         */
	    usage(BADARGS);
    }

     hostname = argv[1];

     /* 
      * PRAC1: Merge `name_to_IP_addr()` and `connect_to()`
      */
     fd = resolve_and_connect(hostname);
     send_HTTP_request(fd, "/", hostname);
     get_and_output_HTTP_response(fd);
     close(fd);

    return 0;
}
