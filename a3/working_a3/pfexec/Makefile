PROG=		pfexec
MAN=		pfexec.1

#Sources
SRCS=           main.c


CFLAGS+=        -fno-strict-aliasing -fstack-protector-all  \
                -fwrapv -fPIC -Wall -g -O0 -Werror

LDADD=-levent
DPADD=${LIBEVENT}

.include <bsd.prog.mk>

