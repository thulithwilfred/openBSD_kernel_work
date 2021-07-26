#include <stdio.h>
#include <errno.h>
#include <util.h>

/**
 * @brief Testing linking to special libraries
 * 
 * @param argc arg count
 * @param argv args
 * @return int 0 on succes (exit status)
 */
int
main(int argc, char** argv) {
    char buf[FMT_SCALED_STRSIZE];
    long long ninput = 12312369;

    if (!fmt_scaled(ninput, buf)) {
        printf("%lld -> %s\n", ninput, buf);
    } else {
        fprintf(stderr, "fmt scaled failed (eerno %d)", errno);
        return -1;
    }
    return 0;
}