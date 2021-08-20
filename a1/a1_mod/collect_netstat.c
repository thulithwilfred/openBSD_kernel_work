#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>

#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <sys/sched.h>

#include "metrics.h"
#include "log.h"

struct metric_ops netstat_metric_ops = {
	.mo_collect = NULL,
	.mo_free = NULL
};



static void
test1(struct registry *r, void **modpriv) {
    printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n\n");
}

static int
test2(void *modpriv) {
    printf("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n\n");
    return 0;
}

static void
test3(void *modpriv) {
    printf("YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY\n\n");
}


struct metrics_module_ops collect_netstat_ops = {
	.mm_register = test1,
	.mm_collect = test2,
	.mm_free = test3
};