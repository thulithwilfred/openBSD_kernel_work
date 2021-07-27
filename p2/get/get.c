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
    int error, fd;
    struct addrinfo* addressInfo;
    struct sockaddr_in socketAddr;
    struct in_addr ipAddress;

    char* hostname = connectionArgs->hostname;
    int port = connectionArgs->port;
    int ai_family = connectionArgs->ai_family;


    warnx("\n\r\r Port: %d\n\r\r Hostname: %s\n\r\r IPV: %s\n\r\r", port, hostname, ((ai_family == AF_INET) ? "IPV4":"IPV6"));

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
    socketAddr.sin_family = ai_family;	/* IP v4 */
    socketAddr.sin_port = htons(port);	/* Convert port number to network byte order */
    socketAddr.sin_addr.s_addr = ipAddress.s_addr;	/* Copy IP address - already in network byte order */

    
    /* 
     * Create TCP socket 
     */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if(fd < 0) {
	    errx(EXIT_SOCKETERR, "%s", "Error creating socket");
    }

    /*
     * Attempt to connect to server at that address 
     */
    if(connect(fd, (struct sockaddr*)&socketAddr, sizeof(socketAddr)) < 0) {
        errx(EXIT_CONNECT, "%s", "Error Connecting");
    }

    freeaddrinfo(addressInfo); //Connected, no, longer required
    return fd;
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
