#include <stdio.h>
#include <stdlib.h>
#include <err.h>
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
        case HELP:
            errx(EXIT_HELP, "Usage: %s hostname [-p port] [-4 ipv4] [-6 ipv6]", __progname);
        case BADARGS:
            errx(EXIT_INVALARGS, "Usage: %s hostname [-p port] [-4 ipv4] [-6 ipv6]", __progname);
        case BADHOST:
            errx(EXIT_BADHOST, "Unable to resolve IP from hostname");    
    }
    exit(EXIT_USAGE);
}