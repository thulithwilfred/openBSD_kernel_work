#ifndef USAGE_H
#define USAGE_H

typedef enum {BADARGS, BADHOST, HELP} usageTypes;

#define EXIT_INVALARGS -1
#define EXIT_HELP 1
#define EXIT_BADHOST -2
#define EXIT_SOCKETERR -3
#define EXIT_CONNECT -4
#define EXIT_USAGE -10


struct userArgs {
    char* hostname;
    int port;
    int ai_family;
};


/* 
 * Function Prototypes
 */
__dead void usage(usageTypes s);

#endif