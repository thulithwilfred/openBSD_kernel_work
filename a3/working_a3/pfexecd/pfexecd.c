/*
 * COMP3301 - Assingment 3
 *
 * pfexecve response daemon
 * Author	: Wilfred MK
 * SID		: S4428042
 * Riv		: 0.1
 * Last Updated	: 12/10/2021
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * SUCH DAMAGE.
 *
 * @(#)main.c v0.1 (UQ) - Wilfred MK
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <err.h>
#include <syslog.h>
#include <fcntl.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/cdefs.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <sys/tree.h>
#include <sys/un.h>
#include <sys/pfexec.h>
#include <sys/pfexecvar.h>

#include <pwd.h>
#include <event.h>
#include <limits.h>
#include <grp.h>
#include <strings.h>

#include "pfexecd.h"
#define PFEXECD_USER "_pfexecd"

const off_t CONFIG_MAX_SIZE	= 16777216LL;	/* 16 MB */
const size_t BACKLOG		= 8;

struct client {
	TAILQ_ENTRY(client)		 c_entry;
	struct sockaddr_storage		 c_raddr;
	int				 c_fd;
	struct event			 c_readable;
	struct pfexec_req		 c_req;
	struct pfexec_resp		 c_resp;
};

static struct event			 pfd_acceptable;
static TAILQ_HEAD(clhead, client)	 pfd_clients;
static char				*pfd_configbuf;

static void	on_lsock_acceptable(int, short, void *);
static void	on_client_readable(int, short, void *);
static int	process_request(const struct pfexec_req *,
    struct pfexec_resp *, short *);
static void	log_request(const struct pfexec_req *,
    const struct pfexec_resp *, short);

static int permit(const struct pfexec_req *, struct pfexec_resp *,
    const struct rule **);
static int match(const struct pfexec_req *, struct pfexec_resp *,
    struct rule *);

static int parsegid(const char *, gid_t *);
static int uidcheck(const char *, uid_t);
static int parseuid(const char *, uid_t *);
static int gid_from_uid(const char *, gid_t *);
static int set_resp_options(const struct pfexec_req *, struct pfexec_resp *,
    const struct rule *);

static int update_resp_enva(struct pfexec_resp *, char **);

/* Updated by the environment of a request packet */
char **req_environ;

void __dead
usage(const char *arg0)
{
	fprintf(stderr, "Usage: %s [-f] [-c file]\n", arg0);
	fprintf(stderr, "       %s [-c file] -t\n", arg0);
	fprintf(stderr, "\nOptions:\n");
	fprintf(stderr, "  -f            Foreground operation: do not fork or "
	    "daemonise\n");
	fprintf(stderr, "  -c <file>     Use <file> as configuration file "
	    "instead of /etc/pfexecd.conf\n");
	fprintf(stderr, "  -t            Test configuration file: check "
	    "syntax and exit 0 if ok\n");
	exit(1);
}

/*
 * Limit daemon functionality and visibility of vfs
 */
static void
to_jail(void)
{

	if (unveil(NULL, NULL) == -1) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE,
		    "unveil failed (%d) %s", errno, strerror(errno));
		exit(1);
	}

	if (pledge("stdio unix getpw", NULL) == -1) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE,
		    "pledge failed (%d) %s", errno, strerror(errno));
		exit(1);
	}
}

/*
 * Drop root privs and continue as _pfexecd (PFEXECD_USER)
 */
static void
drop_privs(void)
{
	struct passwd *pw;
	if ((pw = getpwnam(PFEXECD_USER)) == NULL)
		err(1, "no such user %s", PFEXECD_USER);

	/*
	 * Drop root privs and continue as non-root user.
	 */
	if (setgroups(1, &pw->pw_gid) ||
	    setresgid(pw->pw_gid, pw->pw_gid, pw->pw_gid) ||
	    setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid)) {
			syslog(LOG_AUTHPRIV | LOG_NOTICE,
			    "failed to drop privs: %d (%s)", errno,
			    strerror(errno));
			exit(1);
	}
}

/*
 * Parse a given .y config file and indicate syntax errors.
 */
static void
parse_config(FILE *f)
{
	extern FILE *yyfp;
	extern int yyparse(void);
	yyfp = f;

	yyparse();

	if (parse_errors) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE,
		    "failed to parse config file, it just DOESNT work\n");
		exit(1);
	}
}

int
main(int argc, char *argv[])
{
	const char *optstring = "fc:t";
	const char *conf = "/etc/pfexecd.conf";
	int daemon = 1, testmode = 0;
	pid_t kid;
	int c;
	int rc, fd, lsock;
	size_t conflen;
	struct stat stat;
	ssize_t done;
	struct sockaddr_un laddr;
	FILE *config_stream;

	TAILQ_INIT(&pfd_clients);

	while ((c = getopt(argc, argv, optstring)) != -1) {
		switch (c) {
		case 'f':
			daemon = 0;
			break;
		case 't':
			testmode = 1;
			break;
		case 'c':
			conf = optarg;
			break;
		default:
			warnx("invalid argument");
			usage(argv[0]);
		}
	}

	fd = open(conf, O_RDONLY);
	if (fd < 0)
		err(1, "open(%s)", conf);
	rc = fstat(fd, &stat);
	if (rc < 0)
		err(1, "fstat(%s)", conf);
	if ((stat.st_mode & S_IFREG) == 0)
		errx(1, "config file %s is not a regular file", conf);
	if (stat.st_size > CONFIG_MAX_SIZE)
		errx(1, "config file %s is too big to be pfexecd.conf", conf);
	conflen = stat.st_size + 1;
	pfd_configbuf = calloc(1, conflen);
	if (pfd_configbuf == NULL)
		err(1, "malloc");

	for (done = 0; done < stat.st_size;) {
		ssize_t rr;
		rr = read(fd, pfd_configbuf + done, conflen - done);
		if (rr < 0)
			err(1, "read(%s)", conf);
		if (rr == 0)
			break;
		done += rr;
	}
	pfd_configbuf[conflen - 1] = '\n';
	close(fd);

	/*
	 * Open the pfexecd listening socket which the kernel will connect
	 * to. We unlink() any old socket file which exists before calling
	 * bind() (it would be nicer to have a pid file and check it first)
	 */
	if (!testmode) {
		lsock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
		if (lsock < 0)
			err(1, "socket");

		bzero(&laddr, sizeof(laddr));
		laddr.sun_len = sizeof(laddr);
		laddr.sun_family = AF_UNIX;
		strlcpy(laddr.sun_path, PFEXECD_SOCK, sizeof(laddr.sun_path));

		unlink(PFEXECD_SOCK);
		if (bind(lsock, (struct sockaddr *)&laddr, sizeof(laddr)))
			err(1, "bind(%s)", PFEXECD_SOCK);
		if (listen(lsock, BACKLOG))
			err(1, "listen(%s)", PFEXECD_SOCK);
	}

	if (daemon && !testmode) {
		kid = fork();
		if (kid < 0) {
			err(1, "fork");
		} else if (kid > 0) {
			/* The parent process exits immediately. */
			return (0);
		}
		umask(0);
		if (setsid() < 0) {
			syslog(LOG_AUTHPRIV | LOG_NOTICE,
			    "setsid failed: %d (%s)", errno, strerror(errno));
			exit(1);
		}
		chdir("/");

		close(STDIN_FILENO);
		close(STDOUT_FILENO);
		close(STDERR_FILENO);
	}

	/* Drop privileges here */
	drop_privs(); 		/* Will exit on error */
	to_jail();			/* Sandbox this badboi */

	/* TODO: parse configuration file here: do it *after* dropping privs */
	config_stream = fmemopen(pfd_configbuf, conflen, "r");

	if (config_stream == NULL) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE,
		    "fmemopen failed: %d (%s)", errno, strerror(errno));
		exit(1);
	}

	parse_config(config_stream);
	fclose(config_stream);

	/* If we're in config test mode and config parsing was ok, exit now. */
	if (testmode)
		return (0);

	/*
	 * Ignore SIGPIPE if we get it from any of our sockets: we'll poll
	 * them for read/hup/err later and figure it out anyway.
	 */
	signal(SIGPIPE, SIG_IGN);

	event_init();
	event_set(&pfd_acceptable, lsock, EV_READ, on_lsock_acceptable, NULL);
	event_add(&pfd_acceptable, NULL);
	event_dispatch();

	free(pfd_configbuf);
	close(lsock);

	return (0);
}

static void
destroy_client(struct client *client)
{
	TAILQ_REMOVE(&pfd_clients, client, c_entry);
	event_del(&client->c_readable);
	close(client->c_fd);
	free(client);
}

static void
on_lsock_acceptable(int lsock, short evt, void *arg)
{
	struct sockaddr_storage raddr;
	socklen_t slen;
	int newfd, rc;
	struct client *client;
	uid_t uid;
	gid_t gid;

	slen = sizeof(raddr);
	newfd = accept(lsock, (struct sockaddr *)&raddr, &slen);
	if (newfd < 0) {
		switch (errno) {
		case ECONNABORTED:
		case ECONNRESET:
			goto out;
		default:
			syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed to accept "
			    "connection, aborting: %d (%s)", errno,
			    strerror(errno));
			exit(1);
		}
	}

	/* Check that the process connecting to us is running as "root". */
	rc = getpeereid(newfd, &uid, &gid);
	if (rc != 0) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed to retrieve peer "
		    "uid/gid for new connection, closing");
		close(newfd);
		goto out;
	}
	if (uid != 0 || gid != 0) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "rejecting connection "
		    "from non-root user: uid %d, gid %d", uid, gid);
		close(newfd);
		goto out;
	}

	/*
	 * Set the socket's send buffer size now to make sure there's enough
	 * memory for it.
	 */
	slen = sizeof(struct pfexec_resp) + 32;
	rc = setsockopt(newfd, SOL_SOCKET, SO_SNDBUF, &slen, sizeof(slen));
	if (rc < 0) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed to set send buffer "
		    "size for new client, closing");
		close(newfd);
		goto out;
	}

	client = calloc(1, sizeof(*client));

	if (client == NULL) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed to allocate memory "
		    "for new client, closing");
		close(newfd);
		goto out;
	}

	client->c_fd = newfd;
	bcopy(&raddr, &client->c_raddr, sizeof(raddr));

	TAILQ_INSERT_TAIL(&pfd_clients, client, c_entry);

	event_set(&client->c_readable, newfd, EV_READ, on_client_readable,
	    client);
	event_add(&client->c_readable, NULL);

out:
	event_add(&pfd_acceptable, NULL);
}

static void
on_client_readable(int sock, short evt, void *arg)
{
	struct client *client = (struct client *)arg;
	struct msghdr hdr;
	struct iovec iov;
	ssize_t recvd;
	short log_ok = 0;
	int rc;

	bzero(&hdr, sizeof(hdr));
	bzero(&iov, sizeof(iov));
	bzero(&client->c_req, sizeof(struct pfexec_req));
	hdr.msg_iovlen = 1;
	hdr.msg_iov = &iov;
	iov.iov_base = &client->c_req;
	iov.iov_len = sizeof(struct pfexec_req);

	recvd = recvmsg(sock, &hdr, MSG_DONTWAIT);

	if (recvd < 0) {
		if (errno == EAGAIN)
			goto out;
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed to read request "
		    "from client, closing");
		destroy_client(client);
		return;
	}

	if (recvd == 0) {
		/* EOF: the other end has closed the connection */
		destroy_client(client);
		return;
	}
	if (recvd < sizeof(struct pfexec_req)) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "short request from client, "
		    "closing");
		destroy_client(client);
		return;
	}

	bzero(&client->c_resp, sizeof(struct pfexec_resp));
	rc = process_request(&client->c_req, &client->c_resp, &log_ok);
	if (rc != 0) {
		bzero(&client->c_resp, sizeof(struct pfexec_resp));
		client->c_resp.pfr_errno = rc;
	}
	log_request(&client->c_req, &client->c_resp, log_ok);

	bzero(&hdr, sizeof(hdr));
	bzero(&iov, sizeof(iov));
	hdr.msg_iovlen = 1;
	hdr.msg_iov = &iov;
	iov.iov_base = &client->c_resp;
	iov.iov_len = sizeof(struct pfexec_resp);
	recvd = sendmsg(sock, &hdr, MSG_EOR);
	if (recvd < 0) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE, "failed to write to client, "
		    "closing");
		destroy_client(client);
		return;
	}
out:
	/* End connection to particular request, its completed */
	destroy_client(client);
}

static int
process_request(const struct pfexec_req *req, struct pfexec_resp *resp,
    short *log_ok)
{
	uint i;
	const struct rule *rule;

	/* Check for correctly formed request. */
	if (req->pfr_ngroups >= NGROUPS_MAX)
		return (EINVAL);
	if (req->pfr_req_flags & ~PFEXECVE_ALL_FLAGS)
		return (EINVAL);
	if (strlen(req->pfr_path) < 1 ||
	    strlen(req->pfr_path) >= PATH_MAX)
		return (EINVAL);
	if (req->pfr_argc >= 1024 || req->pfr_envc >= 1024)
		return (EINVAL);
	if ((req->pfr_req_flags & PFEXECVE_USER) && (
	    strlen(req->pfr_req_user) < 1 ||
	    strlen(req->pfr_req_user) >= LOGIN_NAME_MAX))
		return (EINVAL);

	/*
	 * Validate all the argument and env var references before we try to
	 * use any of them.
	 */
	for (i = 0; i < req->pfr_argc; ++i) {
		const struct pfexec_arg *a = &req->pfr_argp[i];
		if (a->pfa_offset >= ARG_MAX)
			return (EINVAL);
		if (a->pfa_len >= ARG_MAX)
			return (EINVAL);
		if (a->pfa_offset + a->pfa_len >= ARG_MAX)
			return (EINVAL);
	}
	for (i = 0; i < req->pfr_envc; ++i) {
		const struct pfexec_arg *a = &req->pfr_envp[i];
		if (a->pfa_offset >= ARG_MAX)
			return (EINVAL);
		if (a->pfa_len >= ARG_MAX)
			return (EINVAL);
		if (a->pfa_offset + a->pfa_len >= ARG_MAX)
			return (EINVAL);
	}

	/* Determine whether this request should be allowed */
	if (!permit(req, resp, &rule)) {
		syslog(LOG_AUTHPRIV | LOG_INFO, "Request denied");
		return (EPERM);
	}

	/* At this point the *last* matching rule is found */
	if (set_resp_options(req, resp, rule)) {
		syslog(LOG_AUTHPRIV | LOG_INFO, "Request denied,"
		" invalid args in conf");
		return (EPERM);
	}

	/*
	 * Determine Password Requirements
	 * The following 3 features are not supported in this rivision..
	 */
	if (rule->options & PERSIST) {
		syslog(LOG_AUTHPRIV | LOG_DEBUG, "Password persist set");
	}

	if ((rule->options & NOPASS) == 0) {
		syslog(LOG_AUTHPRIV | LOG_DEBUG, "Password Required,"
		" Not Implemented");
		return EPERM;
	}

	if (req->pfr_req_flags & PFEXECVE_NOPROMPT) {
		syslog(LOG_AUTHPRIV | LOG_DEBUG, "Unable to do prompts..");
		return EPERM;
	}

	/* Logging enable by defualt */
	if ((rule->options & NOLOG))
		*log_ok = 0;
	else
		*log_ok = 1;

	return (0);
}

/*
 * Updates particular response fields of the response packet
 * @note function must be called only after permit
 */
static int
set_resp_options(const struct pfexec_req *req, struct pfexec_resp *resp,
    const struct rule *r)
{
	const char *safepath = "/bin:/sbin:/usr/bin:/usr/sbin:"
	    "/usr/local/bin:/usr/local/sbin";
	char **envp;
	struct group *grp;
	char mypwbuf[_PW_BUF_LEN], targpwbuf[_PW_BUF_LEN];
	struct passwd mypwstore, targpwstore;
	struct passwd *mypw, *targpw;
	int i, rv, j = 0, set_count = 0, dup = 0;
	uint32_t gid, test_uid;

	resp->pfr_ngroups = 0;
	if (r->options & SETGROUPS) {
		for (i = 0; r->grplist[i]; ++i) {
			if (i >= NGROUPS_MAX)
				return EINVAL;

			if (parsegid(r->grplist[i], &gid) == -1)
				return EINVAL;

			/* Primary GID */
			if (i == 0) {
				resp->pfr_gid = gid;
				continue;
			}

			for (int z = 0; z < i; ++z) {
				if (resp->pfr_groups[z] == gid)
					dup = 1;
			}
			/* Aleady in list, skip ahead */
			if (dup) {
				dup = 0;
				continue;
			}
			resp->pfr_groups[set_count] = gid;
			set_count++;
		}
		resp->pfr_ngroups = set_count; 	/* Count of actual elements */
	} else {
		/*
		 * Get groups of target user,
		 * by looking through group database
		 */
		/* Look for groups of target */
		test_uid = resp->pfr_uid;
		if (r->options & KEEPGROUPS) {
			/* Look for groups of org user */
			test_uid = req->pfr_uid;
			resp->pfr_gid = req->pfr_gid;
		}
		while ((grp = getgrent()) != NULL) {
			for (i = 0; grp->gr_mem[i] != NULL; ++i)
				if (uidcheck(grp->gr_mem[i], test_uid) == 0) {
					/* This groups is primary */
					if (grp->gr_gid == resp->pfr_gid)
						continue;
					/*
					 * Target user is a member of this group
					 */
					resp->pfr_groups[j] = grp->gr_gid;
					j = ++resp->pfr_ngroups;
				}
			if (j >= NGROUPS_MAX)
				return EINVAL;
		}
		endgrent();
	}

	resp->pfr_flags |= PFRESP_GROUPS;

	/* Chroot set */
	if (r->options & CHROOT) {
		if (r->chroot_path) {
			if (strnlen(r->chroot_path, PATH_MAX) >= PATH_MAX - 1)
				return EINVAL;

			strncpy(resp->pfr_chroot, r->chroot_path, PATH_MAX - 1);
		} else {
			strcpy(resp->pfr_chroot, "/var/empty");
		}
		resp->pfr_flags |= PFRESP_CHROOT;
	}

	/* Generate default environ, update current PATH to a safer path */
	if (setenv("PATH", safepath, 1) == -1) {
		syslog(LOG_AUTHPRIV | LOG_INFO,
		    "failed to set PATH '%s'", safepath);
		return EINVAL;
	}

	/* Calling proc */
	rv = getpwuid_r(req->pfr_uid, &mypwstore, mypwbuf,
	    sizeof(mypwbuf), &mypw);

	if (rv != 0) {
		syslog(LOG_AUTHPRIV | LOG_INFO,
		    "getpwuid_r failed for calling proc");
		return EINVAL;
	}
	if (mypw == NULL) {
		syslog(LOG_AUTHPRIV | LOG_INFO,
		    "no passwd entry for calling uid: %d", req->pfr_uid);
		return EINVAL;
	}

	if (req->pfr_req_flags & PFEXECVE_USER) {
		/* Run as proc (Target) */
		rv = getpwnam_r(req->pfr_req_user, &targpwstore, targpwbuf,
		    sizeof(targpwbuf), &targpw);
	} else {
		/* Run as root by def */
		rv = getpwnam_r("root", &targpwstore, targpwbuf,
		    sizeof(targpwbuf), &targpw);
	}

	if (rv != 0) {
		syslog(LOG_AUTHPRIV | LOG_INFO,
		    "getpwuid_r failed for target proc");
		return EINVAL;
	}

	if (targpw == NULL) {
		syslog(LOG_AUTHPRIV | LOG_INFO,
		    "no passwd entry for target uid: %d", req->pfr_uid);
		return EINVAL;
	}

	/* Setup Environ from Request */
	req_environ = malloc(sizeof(char *) * req->pfr_envc + 1);

	for (i = 0; i < req->pfr_envc; ++i) {
		if (req->pfr_envp[i].pfa_offset > ARG_MAX ||
		    req->pfr_envp[i].pfa_len > ARG_MAX) {
			req_environ[i] = NULL;
			goto free_env;
		}

		req_environ[i] = malloc(sizeof(char) *
		    req->pfr_envp[i].pfa_len + 1);

		memset(req_environ[i], 0, req->pfr_envp[i].pfa_len + 1);
		strncpy(req_environ[i], req->pfr_envarea +
		    req->pfr_envp[i].pfa_offset, req->pfr_envp[i].pfa_len);
	}

	/* Used for freeing later */
	req_environ[i] = NULL;		/* Indicate End of data */

	envp = prepenv(r, mypw, targpw);

	/* Update response env buffer */
	if (update_resp_enva(resp, envp))
		goto free_env2;

	/* Free all the things */
	for (i = 0; req_environ[i] != NULL; ++i) {
		free(req_environ[i]);
	}

	/* Free envp string */
	for (i = 0; envp[i] != NULL; ++i) {
		free(envp[i]);
	}

	/* Indicate new env is set for response */
	resp->pfr_flags |= PFRESP_ENV;

	return (0);

	/* Bad returns */
free_env2:
	for (i = 0; envp[i] != NULL; ++i) {
		free(envp[i]);
	}
free_env:
	for (i = 0; req_environ[i] != NULL; ++i) {
		free(req_environ[i]);
	}
	return EINVAL;
}

/*
 * Update response packet environment area.
 */
static int
update_resp_enva(struct pfexec_resp *resp, char **envp)
{
	int i, rc;
	size_t len = 0, offset = 0;
	resp->pfr_envc = 0;

	for (i = 0; envp[i] != NULL; ++i) {
		len = strnlen(envp[i], ARG_MAX);

		if (len > ARG_MAX - offset - 1)
			return E2BIG;

		rc = strlcat(resp->pfr_envarea, envp[i], ARG_MAX - offset - 1);

		if (rc >= (ARG_MAX - offset - 1))
			return E2BIG;

		resp->pfr_envc++;
		resp->pfr_envp[i].pfa_offset = offset;
		resp->pfr_envp[i].pfa_len = len;

		offset += len;
	}
	return (0);
}

/*
 * Validate if a given rule is permitted or not
 * Update the response structure as required on match
 */
static int
permit(const struct pfexec_req *req, struct pfexec_resp *resp,
    const struct rule **lastr)
{
	size_t i;
	*lastr = NULL;

	for (i = 0; i < nrules; i++) {
		if (match(req, resp, rules[i])) {
			*lastr = rules[i];
		}
	}
	if (!*lastr)
		return 0;
	return (*lastr)->action == PERMIT;
}

/*
 * Match a specified to pfexec request.
 * On success, updates the response buffer with final target uid and gid.
 */
static int
match(const struct pfexec_req *req, struct pfexec_resp *resp, struct rule *r)
{

	uint32_t uid = req->pfr_uid;
	uint32_t ngroups = req->pfr_ngroups;
	uint32_t *groups = (uint32_t *)req->pfr_groups;

	uid_t uid_req_user;
	gid_t rgid, target_gid;
	char *test_arg;

	int i;

	if (r->ident[0] == ':') {
		if (parsegid(r->ident + 1, &rgid) == -1)
			return 0;
		for (i = 0; i < ngroups; i++) {
			if (rgid == groups[i])
				break;
		}
		if (i == ngroups)
			return 0;
	} else {
		if (uidcheck(r->ident, uid) != 0)
			return 0;
	}

	/* If target specified and target requested, these must match user */
	if (r->target && r->target[0] == '_') {
		/* Check that the requested user UID matched */
		if (req->pfr_req_flags & PFEXECVE_USER)	{
			if (parseuid(req->pfr_req_user, &uid_req_user) != 0) {
				return 0;
			}
			if (uid_req_user != req->pfr_uid)
				return 0;
			uid_req_user = req->pfr_uid;
			target_gid = req->pfr_gid;
		} else {
			uid_req_user = req->pfr_uid;
			target_gid = req->pfr_gid;
		}
	} else if (r->target && !(req->pfr_req_flags & PFEXECVE_USER)) {
		if (parseuid(r->target, &uid_req_user) != 0)
			return 0;

		if (gid_from_uid(r->target, &target_gid) != 0)
			return 0;
	} else if (r->target && (req->pfr_req_flags & PFEXECVE_USER) != 0) {
		if (parseuid(req->pfr_req_user, &uid_req_user) != 0)
			return 0;

		if (uidcheck(r->target, uid_req_user) != 0)
			return 0;

		/* Target UID matched with reqeusted, get gid */
		if (gid_from_uid(r->target, &target_gid) != 0)
			return 0;

	} else if ((req->pfr_req_flags & PFEXECVE_USER) != 0) {
		/* Run as requested target, no rule restrictions */
		if (parseuid(req->pfr_req_user, &uid_req_user) != 0)
			return 0;

		if (gid_from_uid(req->pfr_req_user, &target_gid) != 0)
			return 0;

	} else {
		/* If no target specified, set default to root */
		if (parseuid("root", &uid_req_user) != 0)
			return 0;

		if (gid_from_uid("root", &target_gid) != 0)
			return 0;
	}

	/* Check for command specifications */
	if (r->cmd) {
		if (strcmp(r->cmd, req->pfr_path))
			return 0;

		/* Given args must be a 1:1 match */
		if (r->cmdargs) {
			test_arg = malloc(sizeof(char) * ARG_MAX);

			for (i = 0; r->cmdargs[i]; ++i) {
				/*
				 * More in rule than requested
				 * pfr_argc contains bin name
				 */
				if (i >= req->pfr_argc - 1) {
					free(test_arg);
					return 0;
				}

				memcpy(test_arg, req->pfr_argarea +
				    req->pfr_argp[i+1].pfa_offset,
				    req->pfr_argp[i+1].pfa_len);

				test_arg[req->pfr_argp[i+1].pfa_len + 1] = '\0';

				if (strcmp(r->cmdargs[i], test_arg)) {
					free(test_arg);
					return 0;
				}
				bzero(test_arg, sizeof(char) * ARG_MAX);
			}
			free(test_arg);
			/*
			 * More args requested than in rule,
			 * (pfr_argc contains bin name)
			 */
			if (i != req->pfr_argc - 1) {
				return 0;
			}
		}
	}

	/* Update response IDs and flags */
	resp->pfr_flags = (PFRESP_UID | PFRESP_GID);
	resp->pfr_uid = uid_req_user;
	resp->pfr_gid = target_gid;
	return 1;
}

/*
 * Validate a specified gid
 */
static int
parsegid(const char *s, gid_t *gid)
{
	struct group *gr;
	const char *errstr;

	if ((gr = getgrnam(s)) != NULL) {
		*gid = gr->gr_gid;
		if (*gid == GID_MAX)
			return -1;
		return 0;
	}
	*gid = strtonum(s, 0, GID_MAX - 1, &errstr);
	if (errstr)
		return -1;
	return 0;
}

/*
 * Test a desired uid matches username
 */
static int
uidcheck(const char *s, uid_t desired)
{
	uid_t uid;
	if (parseuid(s, &uid) != 0)
		return -1;
	if (uid != desired)
		return -1;
	return 0;
}

/*
 * Get a uid from username
 */
static int
parseuid(const char *s, uid_t *uid)
{
	struct passwd *pw;
	const char *errstr;

	if ((pw = getpwnam(s)) != NULL) {
		*uid = pw->pw_uid;
		if (*uid == UID_MAX)
			return -1;
		return 0;
	}
	*uid = strtonum(s, 0, UID_MAX - 1, &errstr);
	if (errstr)
		return -1;
	return 0;
}

/*
 * Get gid from a given username
 */
static int
gid_from_uid(const char *s, gid_t *gid)
{
	struct passwd *pw;
	const char *errstr;

	if ((pw = getpwnam(s)) != NULL) {
		*gid = pw->pw_gid;
		if (*gid == GID_MAX)
			return -1;
		return 0;
	}
	*gid = strtonum(s, 0, GID_MAX - 1, &errstr);
	if (errstr)
		return -1;
	return 0;
}


static void
log_request(const struct pfexec_req *req, const struct pfexec_resp *resp,
    short log_ok)
{
	const char *requser = (req->pfr_req_flags & PFEXECVE_USER) ?
	    req->pfr_req_user : "root";
	if (resp->pfr_errno == 0 && log_ok) {
		syslog(LOG_AUTHPRIV | LOG_INFO,
		    "uid %d ran command %s as %s (pid %d)",
		    req->pfr_uid, req->pfr_path, requser, req->pfr_pid);
		return;
	}
	if (resp->pfr_errno == EPERM) {
		syslog(LOG_AUTHPRIV | LOG_NOTICE,
		    "denied escalation for pid %d (%s) as %s, run by uid %d",
		    req->pfr_pid, req->pfr_path, requser, req->pfr_uid);
		return;
	}
	syslog(LOG_AUTHPRIV | LOG_NOTICE,
	    "error processing esclation request from pid %d, run by uid %d: "
	    "%d: %s", req->pfr_pid, req->pfr_uid, resp->pfr_errno,
	    strerror(resp->pfr_errno));
}