#ifndef USAGE_H
#define USAGE_H

typedef enum {BADARGS, INVALIDMSG, BADHOST} usageTypes;

#define EXIT_INVALARGS -1
#define EXIT_BADHOST -2
#define EXIT_SOCKETERR -3
#define EXIT_CONNECT -4
#define EXIT_USAGE -10


/* 
 * Function Prototypes
 */
__dead void usage(usageTypes s);

#endif