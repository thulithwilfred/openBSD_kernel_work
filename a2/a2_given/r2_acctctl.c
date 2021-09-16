/*
 * Copyright 2021, The University of Queensland
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $Revision: 321 $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <fcntl.h>
#include <poll.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <dev/acct.h>

#define	DEVPATH		"/dev/acct"

enum exit_status {
	EXIT_OK		= 0,
	EXIT_USAGE	= 1,
	EXIT_OPEN	= 2,
	EXIT_IOCTL	= 3,
	EXIT_READ	= 4,
	EXIT_TIME	= 5
};

typedef int (*opt_parser_t)(int c, const char *optarg);
typedef int (*subcom_hdlr_t)(const char *arg0, int argc, char *argv[]);

struct subcommand {
	const char	*sc_name;
	const char	*sc_synopsis;
	const char	*sc_help;
	const char	*sc_optstring;
	opt_parser_t	 sc_parser;
	subcom_hdlr_t	 sc_handler;
};

static int cmd_status(const char *, int, char *[]);
static int cmd_enable(const char *, int, char *[]);
static int cmd_disable(const char *, int, char *[]);
static int cmd_track(const char *, int, char *[]);
static int cmd_untrack(const char *, int, char *[]);
static int cmd_watch(const char *, int, char *[]);

static int opt_watch(int, const char *);

struct subcommand subcoms[] = {
	{
		.sc_name = "status",
		.sc_synopsis = "status",
		.sc_help = "Prints the current status of the accounting "
		    "driver.",
		.sc_optstring = NULL,
		.sc_parser = NULL,
		.sc_handler = cmd_status
	},
	{
		.sc_name = "status",
		.sc_synopsis = "status /path/to/file",
		.sc_help = "Prints the current set of events and conditions "
		    "being audited for the specified file.",
		.sc_optstring = NULL,
		.sc_parser = NULL,
		.sc_handler = cmd_status
	},
	{
		.sc_name = "enable",
		.sc_synopsis = "enable fork|exec|exit|open|close|rename|unlink"
		    " ...",
		.sc_help = "Enables the given auditing feature (or set of "
		    "features, separated by spaces).",
		.sc_optstring = NULL,
		.sc_parser = NULL,
		.sc_handler = cmd_enable
	},
	{
		.sc_name = "disable",
		.sc_synopsis = "disable fork|exec|exit|open|close|rename|unlink"
		    " ...",
		.sc_help = "Disables the given auditing feature (or set of "
		    "features, separated by spaces)."
		    "\n\n"
		    "Disabling all of the open/close/rename/unlink file "
		    "features will result in untracking all tracked files.",
		.sc_optstring = NULL,
		.sc_parser = NULL,
		.sc_handler = cmd_disable
	},
	{
		.sc_name = "track",
		.sc_synopsis = "track /path/to/file [open|unlink|rename] ... "
		    "[read|write|success|failure] ...",
		.sc_help = "Enables file open() tracking for a particular "
		    "path, optionally limited to a particular set of events "
		    "and conditions (separated by spaces). If the file given "
		    "is already being tracked, the events/conditions will be "
		    "added to the existing event set."
		    "\n\n"
		    "The file must already exist on the system to be tracked. "
		    "If no event/condition arguments are given, starts "
		    "tracking all possible events.",
		.sc_optstring = NULL,
		.sc_parser = NULL,
		.sc_handler = cmd_track
	},
	{
		.sc_name = "untrack",
		.sc_synopsis = "untrack /path/to/file [open|unlink|rename] ... "
		    "[read|write|suc...] ...",
		.sc_help = "Disables file open() tracking for a particular "
		    "path. If events or conditions are given, removes those "
		    "events and conditions from the events currently audited. "
		    "If the resulting set of events or conditions is empty, "
		    "stops tracking the file altogether. If no "
		    "event/condition arguments are given, removes all "
		    "possible.",
		.sc_optstring = NULL,
		.sc_parser = NULL,
		.sc_handler = cmd_untrack
	},
	{
		.sc_name = "watch",
		.sc_synopsis = "watch [-j]",
		.sc_help = "Reads audit records from the accounting device, "
		    "printing their contents until interrupted or killed."
		    "\n\n"
		    "If -j is given, prints audit records as JSON objects.",
		.sc_optstring = "j",
		.sc_parser = opt_watch,
		.sc_handler = cmd_watch
	},
	{
		.sc_name = NULL
	}
};

static void
wrap_print(const char *str)
{
	char *tmp, *p, *t;
	char tch;

	tmp = strdup(str);
	p = tmp;

	while (strlen(p) > 70 || strchr(p, '\n') != NULL) {
		t = strchr(p, '\n');
		if (t != NULL && (t - p) < 70) {
			*t = '\0';
			fprintf(stderr, "    %s\n", p);
			p = t + 1;
			continue;
		}
		tch = p[70];
		p[70] = '\0';
		t = strrchr(p, ' ');
		if (t == NULL)
			t = &p[69];
		p[70] = tch;

		*t = '\0';
		fprintf(stderr, "    %s\n", p);
		p = t + 1;
	}
	fprintf(stderr, "    %s\n", p);
	free(tmp);
}

static __dead void
usage(const char *arg0)
{
	const struct subcommand *sc;

	fprintf(stderr, "usage: %s operation [options] [args]\n", arg0);
	fprintf(stderr, "\noperations:\n");
	for (sc = &subcoms[0]; sc->sc_name != NULL; ++sc) {
		fprintf(stderr, "\n  %s\n\n", sc->sc_synopsis);
		wrap_print(sc->sc_help);
	}
	exit(EXIT_USAGE);
}

int
main(int argc, char *argv[])
{
	const char *op;
	const struct subcommand *sc;
	int c, rc;
	const char *arg0 = argv[0];
	const char *optstring;

	if (argc < 2)
		usage(arg0);
	op = argv[1];
	argc -= 1;
	argv += 1;

	for (sc = &subcoms[0]; sc->sc_name != NULL; ++sc) {
		if (strcmp(sc->sc_name, op) == 0) {
			break;
		}
	}
	if (sc->sc_name == NULL)
		usage(arg0);

	if (sc->sc_optstring == NULL)
		optstring = "h";
	else
		optstring = sc->sc_optstring;

	while ((c = getopt(argc, argv, optstring)) != -1) {
		if (c == 'h' || c == '?')
			usage(arg0);

		rc = sc->sc_parser(c, optarg);
		if (rc != 0) {
			warnx("failed to parse cmdline args");
			usage(arg0);
		}
	}
	argc -= optind;
	argv += optind;

	rc = sc->sc_handler(arg0, argc, argv);
	return (rc);
}

static void
print_ena(int ena)
{
	printf("events enabled:");
	if (ena & ACCT_ENA_FORK)
		printf(" fork");
	if (ena & ACCT_ENA_EXEC)
		printf(" exec");
	if (ena & ACCT_ENA_EXIT)
		printf(" exit");
	if (ena & ACCT_ENA_OPEN)
		printf(" open");
	if (ena & ACCT_ENA_CLOSE)
		printf(" close");
	if (ena & ACCT_ENA_RENAME)
		printf(" rename");
	if (ena & ACCT_ENA_UNLINK)
		printf(" unlink");
	if (ena == 0)
		printf(" (none)");
	printf("\n");
}

static void
print_cond(int conds)
{
	printf("conditions:");
	if (conds & ACCT_COND_READ)
		printf(" read");
	if (conds & ACCT_COND_WRITE)
		printf(" write");
	if (conds & ACCT_COND_SUCCESS)
		printf(" success");
	if (conds & ACCT_COND_FAILURE)
		printf(" failure");
	if (conds == 0)
		printf(" (none)");
	printf("\n");
}

static uint32_t
ena_mask_from_str(const char *str)
{
	if (strcmp(str, "fork") == 0) {
		return (ACCT_ENA_FORK);
	} else if (strcmp(str, "exec") == 0) {
		return (ACCT_ENA_EXEC);
	} else if (strcmp(str, "exit") == 0) {
		return (ACCT_ENA_EXIT);
	} else if (strcmp(str, "open") == 0) {
		return (ACCT_ENA_OPEN);
	} else if (strcmp(str, "close") == 0) {
		return (ACCT_ENA_CLOSE);
	} else if (strcmp(str, "rename") == 0) {
		return (ACCT_ENA_RENAME);
	} else if (strcmp(str, "unlink") == 0) {
		return (ACCT_ENA_UNLINK);
	} else if (strcmp(str, "all") == 0) {
		return (ACCT_ENA_ALL);
	} else {
		return (0);
	}
}

static uint32_t
cond_mask_from_str(const char *str)
{
	if (strcmp(str, "read") == 0) {
		return (ACCT_COND_READ);
	} else if (strcmp(str, "write") == 0) {
		return (ACCT_COND_WRITE);
	} else if (strcmp(str, "success") == 0) {
		return (ACCT_COND_SUCCESS);
	} else if (strcmp(str, "failure") == 0) {
		return (ACCT_COND_FAILURE);
	} else if (strcmp(str, "all") == 0) {
		return (ACCT_COND_ALL);
	} else {
		return (0);
	}
}

static int
cmd_status(const char *arg0, int argc, char *argv[])
{
	int fd, rc;
	struct acct_ctl ctl;

	bzero(&ctl, sizeof(struct acct_ctl));

	fd = open(DEVPATH, O_RDWR | O_EXLOCK);
	if (fd < 0)
		err(EXIT_OPEN, "open(" DEVPATH ")");

	if (argc == 0) {
		rc = ioctl(fd, ACCT_IOC_STATUS, &ctl);
		if (rc < 0)
			err(EXIT_IOCTL, "ioctl(ACCT_IOC_STATUS)");

		print_ena(ctl.acct_ena);
		printf("number of monitored files: %llu\n", ctl.acct_fcount);
	} else {
		strlcpy(ctl.acct_path, argv[0], sizeof(ctl.acct_path));
		rc = ioctl(fd, ACCT_IOC_FSTATUS, &ctl);
		if (rc < 0)
			err(EXIT_IOCTL, "ioctl(ACCT_IOC_FSTATUS)");

		print_ena(ctl.acct_ena);
		print_cond(ctl.acct_cond);
	}

	close(fd);

	return (0);
}

static int
cmd_enable(const char *arg0, int argc, char *argv[])
{
	int fd, rc, i;
	uint32_t mask;
	struct acct_ctl ctl;

	fd = open(DEVPATH, O_RDWR | O_EXLOCK);
	if (fd < 0)
		err(EXIT_OPEN, "open(" DEVPATH ")");

	bzero(&ctl, sizeof(struct acct_ctl));
	for (i = 0; i < argc; ++i) {
		mask = ena_mask_from_str(argv[i]);
		if (mask == 0) {
			warnx("unknown auditing feature: '%s'", argv[i]);
			usage(arg0);
		}
		ctl.acct_ena |= mask;
	}
	if (ctl.acct_ena == 0)
		ctl.acct_ena = ACCT_ENA_ALL;

	rc = ioctl(fd, ACCT_IOC_ENABLE, &ctl);
	if (rc < 0)
		err(EXIT_IOCTL, "ioctl(ACCT_IOC_ENABLE)");

	print_ena(ctl.acct_ena);

	close(fd);

	return (0);
}

static int
cmd_disable(const char *arg0, int argc, char *argv[])
{
	int fd, rc, i;
	struct acct_ctl ctl;
	uint32_t mask;

	fd = open(DEVPATH, O_RDWR | O_EXLOCK);
	if (fd < 0)
		err(EXIT_OPEN, "open(" DEVPATH ")");

	bzero(&ctl, sizeof(struct acct_ctl));
	for (i = 0; i < argc; ++i) {
		mask = ena_mask_from_str(argv[i]);
		if (mask == 0) {
			warnx("unknown auditing feature: '%s'", argv[i]);
			usage(arg0);
		}
		ctl.acct_ena |= mask;
	}
	if (ctl.acct_ena == 0)
		ctl.acct_ena = ACCT_ENA_ALL;

	rc = ioctl(fd, ACCT_IOC_DISABLE, &ctl);
	if (rc < 0)
		err(EXIT_IOCTL, "ioctl(ACCT_IOC_ENABLE)");

	print_ena(ctl.acct_ena);

	close(fd);

	return (0);
}

static int
cmd_track(const char *arg0, int argc, char *argv[])
{
	const char *path;
	int fd, i, rc;
	struct acct_ctl ctl;
	uint32_t mask;

	bzero(&ctl, sizeof(struct acct_ctl));

	if (argc == 0) {
		warnx("track: path required");
		usage(arg0);
	}
	path = argv[0];

	for (i = 1; i < argc; ++i) {
		mask = ena_mask_from_str(argv[i]);
		if (mask == 0) {
			mask = cond_mask_from_str(argv[i]);
			if (mask == 0) {
				warnx("unknown event/cond: '%s'", argv[i]);
				usage(arg0);
			}
			ctl.acct_cond |= mask;
		} else {
			ctl.acct_ena |= mask;
		}
	}
	if (ctl.acct_ena == 0)
		ctl.acct_ena = ACCT_ENA_ALL;
	if (ctl.acct_cond == 0)
		ctl.acct_cond = ACCT_COND_ALL;

	strlcpy(ctl.acct_path, path, sizeof(ctl.acct_path));

	fd = open(DEVPATH, O_RDWR | O_EXLOCK);
	if (fd < 0)
		err(EXIT_OPEN, "open(" DEVPATH ")");

	rc = ioctl(fd, ACCT_IOC_TRACK_FILE, &ctl);
	if (rc < 0)
		err(EXIT_IOCTL, "ioctl(ACCT_IOC_TRACK_FILE)");

	close(fd);

	print_ena(ctl.acct_ena);
	print_cond(ctl.acct_cond);

	return (0);
}

static int
cmd_untrack(const char *arg0, int argc, char *argv[])
{
	const char *path;
	int fd, i, rc;
	struct acct_ctl ctl;
	uint32_t mask;

	bzero(&ctl, sizeof(struct acct_ctl));

	if (argc == 0) {
		warnx("untrack: path required");
		usage(arg0);
	}
	path = argv[0];

	for (i = 1; i < argc; ++i) {
		mask = ena_mask_from_str(argv[i]);
		if (mask == 0) {
			mask = cond_mask_from_str(argv[i]);
			if (mask == 0) {
				warnx("unknown event/cond: '%s'", argv[i]);
				usage(arg0);
			}
			ctl.acct_cond |= mask;
		} else {
			ctl.acct_ena |= mask;
		}
	}
	if (ctl.acct_ena == 0)
		ctl.acct_ena = ACCT_ENA_ALL;
	if (ctl.acct_cond == 0)
		ctl.acct_cond = ACCT_COND_ALL;

	strlcpy(ctl.acct_path, path, sizeof(ctl.acct_path));

	fd = open(DEVPATH, O_RDWR | O_EXLOCK);
	if (fd < 0)
		err(EXIT_OPEN, "open(" DEVPATH ")");

	rc = ioctl(fd, ACCT_IOC_UNTRACK_FILE, &ctl);
	if (rc < 0)
		err(EXIT_IOCTL, "ioctl(ACCT_IOC_UNTRACK_FILE)");

	close(fd);

	print_ena(ctl.acct_ena);
	print_cond(ctl.acct_cond);

	return (0);
}

static int json_mode = 0;

static void
print_abs_time(struct timespec ts)
{
	struct timeval tv;
	struct tm *info;

	bzero(&tv, sizeof(tv));
	tv.tv_sec = ts.tv_sec;
	tv.tv_usec = ts.tv_nsec / 1000;

	if (gettimeofday(&tv, NULL))
		err(EXIT_TIME, "gettimeofday()");
	info = gmtime(&tv.tv_sec);
	if (info == NULL)
		err(EXIT_TIME, "gmtime");

	printf("%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
	    info->tm_year + 1900, info->tm_mon + 1, info->tm_mday,
	    info->tm_hour, info->tm_min, info->tm_sec, tv.tv_usec / 1000);
}

static void
print_common(struct acct_common *msg, const char *evt)
{
	if (json_mode) {
		printf("{\"time\":\"");
		print_abs_time(msg->ac_btime);
		printf("\",\"event\":\"%s\"", evt);
		printf(",\"pid\":%d,\"uid\":%d,\"gid\":%d,\"tty\":[%d,%d]",
		    msg->ac_pid, msg->ac_uid, msg->ac_gid, major(msg->ac_tty),
		    minor(msg->ac_tty));
		if (strlen(msg->ac_comm) > 0)
			printf(",\"command\":\"%s\"", msg->ac_comm);
	} else {
		printf("[");
		print_abs_time(msg->ac_btime);
		printf("] %s ", evt);
		printf("pid=%d uid=%d gid=%d tty=%d:%d", msg->ac_pid,
		    msg->ac_uid, msg->ac_gid, major(msg->ac_tty),
		    minor(msg->ac_tty));
		if (strlen(msg->ac_comm) > 0)
			printf(" cmd='%s'", msg->ac_comm);
	}
}

static void
print_msg_fork(struct acct_fork *msg)
{
	print_common(&msg->ac_common, "fork");
	if (json_mode) {
		printf(",\"child\":%d}\n", msg->ac_cpid);
	} else {
		printf(" child=%d\n", msg->ac_cpid);
	}
}

static void
print_msg_exec(struct acct_exec *msg)
{
	print_common(&msg->ac_common, "exec");
	if (json_mode)
		printf("}\n");
	else
		printf("\n");
}

static void
print_msg_exit(struct acct_exit *msg)
{
	print_common(&msg->ac_common, "exit");
	if (json_mode) {
		printf(",\"user_time\":%llu.%012lu",
		    msg->ac_utime.tv_sec, msg->ac_utime.tv_nsec);
		printf(",\"sys_time\":%llu.%012lu",
		    msg->ac_stime.tv_sec, msg->ac_stime.tv_nsec);
		printf(",\"avg_mem\":%llu", msg->ac_mem);
		printf(",\"io_blocks\":%llu}\n", msg->ac_io);
	} else {
		printf(" utime=%llus stime=%llus mem=%llu io=%llu\n",
		    msg->ac_utime.tv_sec, msg->ac_stime.tv_sec,
		    msg->ac_mem, msg->ac_io);
	}
}

static void
print_msg_open(struct acct_open *msg)
{
	print_common(&msg->ac_common, "open");
	if (json_mode) {
		printf(",\"path\":\"%s\",\"mode\":%d,\"errno\":%d}\n",
		    msg->ac_path, msg->ac_mode, msg->ac_errno);
	} else {
		char mstr[16] = { 0 };

		if (msg->ac_mode & O_RDWR)
			strlcat(mstr, "rw", sizeof(mstr));
		else if (msg->ac_mode & O_WRONLY)
			strlcat(mstr, "w", sizeof(mstr));
		else
			strlcat(mstr, "r", sizeof(mstr));

		if (msg->ac_mode & O_APPEND)
			strlcat(mstr, "a", sizeof(mstr));
		if (msg->ac_mode & O_CREAT)
			strlcat(mstr, "c", sizeof(mstr));
		if (msg->ac_mode & O_TRUNC)
			strlcat(mstr, "t", sizeof(mstr));
		if (msg->ac_mode & O_EXCL)
			strlcat(mstr, "x", sizeof(mstr));
		printf(" path='%s' mode=%s", msg->ac_path, mstr);
		if (msg->ac_errno == 0) {
			printf(" success\n");
		} else {
			printf(" error=%d(%s)\n", msg->ac_errno,
			    strerror(msg->ac_errno));
		}
	}
}

static void
print_msg_rename(struct acct_rename *msg)
{
	print_common(&msg->ac_common, "rename");
	if (json_mode) {
		printf(",\"path\":\"%s\",\"new_path\":\"%s\",\"errno\":%d}\n",
		    msg->ac_path, msg->ac_new, msg->ac_errno);
	} else {
		printf(" path='%s' newpath='%s'", msg->ac_path, msg->ac_new);
		if (msg->ac_errno == 0) {
			printf(" success\n");
		} else {
			printf(" error=%d(%s)\n", msg->ac_errno,
			    strerror(msg->ac_errno));
		}
	}
}

static void
print_msg_unlink(struct acct_unlink *msg)
{
	print_common(&msg->ac_common, "unlink");
	if (json_mode) {
		printf(",\"path\":\"%s\",\"errno\":%d}\n", msg->ac_path,
		    msg->ac_errno);
	} else {
		printf(" path='%s'", msg->ac_path);
		if (msg->ac_errno == 0) {
			printf(" success\n");
		} else {
			printf(" error=%d(%s)\n", msg->ac_errno,
			    strerror(msg->ac_errno));
		}
	}
}

static void
print_msg_close(struct acct_close *msg)
{
	print_common(&msg->ac_common, "close");
	if (json_mode)
		printf(",\"path\":\"%s\"}\n", msg->ac_path);
	else
		printf(" path='%s'\n", msg->ac_path);
}

static int
opt_watch(int c, const char *optarg)
{
	switch (c) {
	case 'j':
		json_mode = 1;
		break;
	default:
		return (-1);
	}
	return (0);
}

union acct_any {
	struct acct_common	common;
        struct acct_fork	fork;
        struct acct_exec	exec;
        struct acct_exit	exit;
        struct acct_open	open;
        struct acct_rename	rename;
        struct acct_unlink	unlink;
        struct acct_close	close;
};

static int
cmd_watch(const char *arg0, int argc, char *argv[])
{
	int fd;
	ssize_t rd;
	union acct_any msg;
	struct acct_common *cmn = &msg.common;
	unsigned int seq = 0;

	fd = open(DEVPATH, O_RDONLY | O_EXLOCK);
	if (fd < 0)
		err(EXIT_OPEN, "open(" DEVPATH ")");

	while (1) {
		bzero(&msg, sizeof (msg));
		rd = read(fd, &msg, sizeof(msg));
		if (rd < 0)
			err(EXIT_READ, "read");
		if (rd == 0 || rd < sizeof(struct acct_common))
			break;
		if (rd < cmn->ac_len) {
			errx(EXIT_READ, "short msg: ac_len = %d, rd = %zd",
			    cmn->ac_len, rd);
		}
		if (cmn->ac_seq != seq++)
			fprintf(stderr, "warning: events dropped\n");
		switch (cmn->ac_type) {
		case ACCT_MSG_FORK:
			if (rd < sizeof(msg.fork))
				errx(EXIT_READ, "short fork msg: rd = %zd", rd);
			print_msg_fork(&msg.fork);
			break;
		case ACCT_MSG_EXEC:
			if (rd < sizeof(msg.exec))
				errx(EXIT_READ, "short exec msg: rd = %zd", rd);
			print_msg_exec(&msg.exec);
			break;
		case ACCT_MSG_EXIT:
			if (rd < sizeof(msg.exit))
				errx(EXIT_READ, "short exit msg: rd = %zd", rd);
			print_msg_exit(&msg.exit);
			break;
		case ACCT_MSG_OPEN:
			if (rd < sizeof(msg.open))
				errx(EXIT_READ, "short open msg: rd = %zd", rd);
			print_msg_open(&msg.open);
			break;
		case ACCT_MSG_RENAME:
			if (rd < sizeof(msg.rename))
				errx(EXIT_READ, "short ren msg: rd = %zd", rd);
			print_msg_rename(&msg.rename);
			break;
		case ACCT_MSG_UNLINK:
			if (rd < sizeof(msg.unlink))
				errx(EXIT_READ, "short unl msg: rd = %zd", rd);
			print_msg_unlink(&msg.unlink);
			break;
		case ACCT_MSG_CLOSE:
			if (rd < sizeof(msg.close))
				errx(EXIT_READ, "short cls msg: rd = %zd", rd);
			print_msg_close(&msg.close);
			break;
		default:
			errx(EXIT_READ, "received invalid audit msg: %d",
			    cmn->ac_type);
		}
	}

	close(fd);

	return (0);
}
