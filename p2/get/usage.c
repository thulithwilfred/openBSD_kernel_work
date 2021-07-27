#include <stdio.h>
#include <stdlib.h>
#include "usage.h"

/**
 * @brief Prints a specific usage message based on the usageType variable,
            messages is printed out into stdout. 
 * 
 * @note Does not return, will exit with errno
 * @param usageType selects which usage message is required
 */
__dead void
usage(usageTypes s) {
     extern char *__progname;

    switch (s) {
        case INVALIDMSG:
        case BADARGS:
            fprintf(stderr, "Usage: %s hostname\n", __progname);
            exit(EXIT_INVALARGS);
        case BADHOST:
            fprintf(stderr, "Unable to resolve IP from hostname\n");
            exit(EXIT_BADHOST);        
    }

    exit(EXIT_USAGE);
}