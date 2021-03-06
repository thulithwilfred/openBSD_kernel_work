/*
 * COMP3301 - Assingment 3
 *
 * syscall handler for pfexecve.
 *
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
 * @(#)kern_pfexec.c v0.1 (UQ) - Wilfred MK
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/exec.h>
#include <sys/resourcevar.h>
#include <sys/signalvar.h>
#include <sys/vnode.h>
#include <sys/vmmeter.h>
#include <sys/acct.h>
#include <sys/ktrace.h>
#include <sys/sched.h>
#include <sys/sysctl.h>
#include <sys/pool.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/atomic.h>
#include <sys/pledge.h>
#include <sys/unistd.h>

#include <sys/pfexec.h>
#include <sys/syscallargs.h>
#include <sys/namei.h>
#include <sys/pfexecvar.h>
#include <sys/ucred.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/mbuf.h>
#include <sys/un.h>
#include <sys/task.h>

#define TASK_ISCOMPLETE 1
#define TASK_PENDING 0

struct task_transeive_pfr;

void connect_pfexecd(void *);
static int parse_response(struct pfexec_resp *);
static int set_creds_check(struct pfexec_resp *);
static int dochroot_tings(struct proc *, struct pfexec_resp *);
char **build_new_env(struct pfexec_resp *);
void free_env(char **,  struct pfexec_resp *);
static int lookup_chroot_path(struct proc *, struct pfexec_resp *);
static int transceive_pfexecd(struct task_transeive_pfr *);

/* Used for debug messaging to process tty */
struct tty *tty;

const struct kmem_va_mode kv_pfexec = {
	.kv_wait = 1,
	.kv_map = &exec_map
};

/* Combining struct for pfexec_connect task and transceive_pfexecd */
struct task_transeive_pfr {
	struct socket *so;
	struct pfexec_req *req;		/* Used in data transmission */
	struct pfexec_resp *resp;
	uint32_t error;				/* Task error indicators */
	uint32_t state;
};

/*
 * Create and return and mbuf cluster chain from the buffer in buf,
 * based on the buffer size tot_len.
 */
struct mbuf *
build_mbuf2(void *buf, int tot_len)
{
	struct mbuf *m;
	struct mbuf *top, **mp;
	int len = 0, offset = 0;

	top = NULL;
	mp = &top;

	while (tot_len > 0) {

		len = (tot_len > MAXMCLBYTES) ? MAXMCLBYTES : tot_len;

		m = MCLGETL(NULL, M_WAIT, len);

		if (m == NULL) {
			m_freem(top);
			return NULL;
		}

		bzero(m->m_data, len);
		memcpy(m->m_data, buf + offset, len);

		offset += len;
		m->m_len = len;
		tot_len -= len;

		*mp = m;
		mp = &m->m_next;
	}

	return (top);
}

/*
 * Send a request to a pfexecd and await response message.
 * Can be interrupted by signals.
 */
static int
transceive_pfexecd(struct task_transeive_pfr *t_pfr)
{
	struct socket *so = t_pfr->so;
	struct pfexec_req *r = t_pfr->req;
	struct pfexec_resp *resp = t_pfr->resp;

	struct mbuf *top = NULL;
	struct mbuf *recv_top = NULL;
	struct uio auio;

	int error = 0, recvflags = 0;

	/* Build MBUF from req packet */
	top = build_mbuf2((void *)r, sizeof(*r));

	if (top == NULL) {
		goto close;
	}

	/* Send Message and wait..., should free top */
	if (!so) {
		error = ENOTCONN;
		goto close;
	}

	error = sosend(so, NULL, NULL, top, NULL, MSG_EOR);

	if (error) {
		error = ENOTCONN;
		goto close;
	}

	/* Recv response, waiting for all data to be received */
	bzero(&auio, sizeof(struct uio));
	auio.uio_procp = NULL;
	auio.uio_resid = sizeof(struct pfexec_resp) + 32;
	recvflags = MSG_WAITALL;
	error = soreceive(so, NULL, &auio, &recv_top, NULL, &recvflags, 0);

	if (error) {
		error = ENOTCONN;
		goto close;
	}

	if (!recv_top) {
		error = ENOTCONN;
		goto close;
	}

	if ((recvflags & MSG_EOR) == 0) {
		error = ENOTCONN;
		goto close;
	}

	/* Copy Daemon Response */
	m_copydata(recv_top, 0, sizeof(struct pfexec_resp), resp);

	/* Release recv mbuf chain */
	m_freem(recv_top);

close:
	soclose(so, MSG_DONTWAIT);
	return (error);
}


/*
 * Attemp a connection with the daemon and sent a message, block whilst
 * waiting for a response. If any errors are occured, ENOTCONN is set in the
 * arg errors.
 */
void
connect_pfexecd(void *arg)
{

	struct task_transeive_pfr *t_pfr = arg;
	struct pfexec_resp *resp = t_pfr->resp;
	struct mbuf *nam = NULL;
	struct sockaddr *sa;
	struct sockaddr_un addr;
	struct socket *so;

	int s, error = 0;

	t_pfr->state = TASK_PENDING;
	t_pfr->error = error;

	/* Create socket */
	if ((error = socreate(AF_UNIX, &so, SOCK_SEQPACKET, 0))) {
		goto close;
	}

	/* Connect to path PFEXECD_SOCK */
	bzero(&addr, sizeof(addr));
	addr.sun_len = sizeof(addr);
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, PFEXECD_SOCK, sizeof(addr.sun_path));

	MGET(nam, M_WAIT, MT_SONAME);
	if (nam == NULL)
		goto close;
	nam->m_len = addr.sun_len;
	sa = mtod(nam, struct sockaddr *);
	memcpy(sa, &addr, addr.sun_len);

	s = solock(so);

	error = soconnect(so, nam);

	if (error)  {
		error = ENOTCONN;
		goto unlock_release;
	}

	while ((so->so_state & SS_ISCONNECTING) && (so->so_error == 0)) {
		error = sosleep_nsec(so, &so->so_timeo, PSOCK | PCATCH,
		    "pfexecve_conn", INFSLP);

		if (error)
			goto unlock_release;
	}

	if (so->so_error) {
		error = so->so_error;
		so->so_error = 0;
		error = ENOTCONN;
		goto unlock_release;
	}

	if (error == 0)
		t_pfr->so = so;
	else {
		soclose(so, MSG_DONTWAIT);
		t_pfr->so = NULL;
	}

unlock_release:
	sounlock(so, s);
close:
	m_freem(nam);
	/* Signal Completion and Error */
	t_pfr->state = TASK_ISCOMPLETE;
	t_pfr->error = error;
	wakeup(resp);
}

/*
 * Validate that a path exists.
 */
static int
lookup_path(const char *path, struct proc *p, struct vnode **vpp)
{
	struct nameidata ndi;
	int rc;
	struct vnode *vp;

	NDINIT(&ndi, LOOKUP, FOLLOW | LOCKLEAF, UIO_USERSPACE, path, p);
	rc = namei(&ndi);

	if (rc != 0)
		return (rc);

	vp = ndi.ni_vp;
	VOP_UNLOCK(vp);
	*vpp = vp;
	return (0);
}

/*
 * pfexec system call.
 */
int
sys_pfexecve(struct proc *p, void *v, register_t *retVal)
{
	struct sys_pfexecve_args /* {
		syscallarg(const struct pfexecve_opts *) opts;
		syscallarg(const char *)  path;
		syscallarg(char *const *) argp;
		syscallarg(char *const *) envp;
	} */ *uap = v;

	struct sys_execve_args /* {
		syscallarg(const char *)  path;
		syscallarg(char *const *) argp;
		syscallarg(char *const *) envp;
	} */ args;

	struct taskq *tq;
	struct task k_task;

	struct process *pr = p->p_p;

	struct ucred *cred = p->p_ucred;
	struct ucred *newcred = NULL;

	const char *file_path;
	struct vnode *vp = NULL;

	struct pfexec_req *req;
	struct pfexec_resp *resp;
	struct pfexecve_opts opts;
	struct task_transeive_pfr t_pfr;

	char **new_env = NULL;
	char *const *cpp, *dp, *sp;
	char *argp;

	size_t len;
	int error = 0, rc = 0, argc, envc;
	uint32_t offset;

	/*
	 * Stop all threads in the calling process other than
	 *   the calling thread
	 */
	if ((error = single_thread_set(p, SINGLE_UNWIND, 1)))
		return (error);

	/* 1. Validity Checks */
	if (SCARG(uap, opts) == NULL)
		return EINVAL;

	if ((error = copyin(SCARG(uap, opts), &opts,
	    sizeof(struct pfexecve_opts))))
		return error;

	/* Check the path to be executed is valid */
	file_path = SCARG(uap, path);

	if (file_path == NULL)
		return ENOENT;

	error = lookup_path(file_path, p, &vp);

	if (error != 0)
		return (error);			/* vnode cannot be resolved */


	/* 2. Setup request packet */
	req = malloc(sizeof(struct pfexec_req), M_EXEC,
	    M_WAITOK | M_ZERO);

	bzero(req, sizeof(struct pfexec_req));
	req->pfr_pid = pr->ps_pid;
	req->pfr_uid = cred->cr_uid;
	req->pfr_gid = cred->cr_gid;
	req->pfr_ngroups = cred->cr_ngroups;

	memcpy(req->pfr_groups, cred->cr_groups,
	    req->pfr_ngroups * sizeof(gid_t));

	req->pfr_req_flags = opts.pfo_flags;

	if (opts.pfo_flags & PFEXECVE_USER) {
		if (*opts.pfo_user == '\0') {
			error = EINVAL;
			goto bad_free_req;
		}
		memcpy(req->pfr_req_user, opts.pfo_user,
		    sizeof(char) * LOGIN_NAME_MAX);
	}

	copyin(file_path, req->pfr_path, sizeof(char) * PATH_MAX);

	/* allocate an argument buffer */
	argp =  malloc(NCARGS, M_EXEC, M_WAITOK | M_ZERO | M_CANFAIL);

	if (argp == NULL) {
		error = ENOMEM;
		goto bad_free_req;
	}

	if (!(cpp = SCARG(uap, argp))) {
		error = EFAULT;
		goto release;
	}

	dp = argp;
	argc = 0;
	offset = 0;

	while (1) {
		len = argp + ARG_MAX - dp;

		if ((error = copyin(cpp, &sp, sizeof(sp))) != 0)
			goto release;

		if (!sp)
			break;

		if ((error = copyinstr(sp, dp, len, &len)) != 0) {
			if (error == ENAMETOOLONG)
				error = E2BIG;
			goto release;
		}

		if (argc >= 1024) {
			error = E2BIG;
			goto release;
		}

		if (offset >= ARG_MAX) {
			error = E2BIG;
			goto release;
		}

		req->pfr_argp[argc].pfa_offset = offset;
		req->pfr_argp[argc].pfa_len = len - 1;	/* Not including NUL */
		/* Max len - current offset into buffer - ONE NUL at the end */
		rc = strlcat(req->pfr_argarea, dp, ARG_MAX - offset - 1);

		if (rc >= (ARG_MAX - offset - 1)) {
			error = E2BIG;
			goto release;
		}

		offset += len - 1;			/* Not including NUL */
		dp += len;
		cpp++;
		argc++;
	}

	/* must have at least one argument */
	if (argc == 0) {
		error = EINVAL;
		goto release;
	}

	req->pfr_argc = argc;

	/* GET ENVIRON */
	envc = 0;
	offset = 0;

	if ((cpp = SCARG(uap, envp)) != NULL) {
		while (1) {
			len = argp + ARG_MAX - dp;
			if ((error = copyin(cpp, &sp, sizeof(sp))) != 0)
				goto release;
			if (!sp)
				break;
			if ((error = copyinstr(sp, dp, len, &len)) != 0) {
				if (error == ENAMETOOLONG)
					error = E2BIG;
				goto release;
			}

			req->pfr_envp[envc].pfa_offset = offset;
			/* No NUL in len */
			req->pfr_envp[envc].pfa_len = len - 1;
			/* Max len - current offset into buffer */
			rc = strlcat(req->pfr_envarea, dp,
			    ARG_MAX - offset - 1);

			if (rc >= (ARG_MAX - offset - 1)) {
				error = E2BIG;
				goto release;
			}

			offset += len - 1;
			dp += len;
			cpp++;
			envc++;
		}
	}

	req->pfr_envc = envc;
	/* Free argp buffer */
	free(argp, M_EXEC, NCARGS);

	/* 3. pfexecd transeivce data */
	tq = taskq_create("conn", 1, IPL_NONE, TASKQ_MPSAFE);
	if (tq == NULL) {
		error = EAGAIN;
		goto bad_free_req;
	}
	/* Allocate for resp struct */
	resp = malloc(sizeof(struct pfexec_resp), M_EXEC, M_WAITOK | M_ZERO);
	bzero(&t_pfr, sizeof(struct task_transeive_pfr));
	t_pfr.req = req;
	t_pfr.resp = resp;

	task_set(&k_task, connect_pfexecd, (void *)&t_pfr);
	error = task_add(tq, &k_task);

	if (error != 1) {
		error = EBUSY;
		taskq_destroy(tq);
		goto bad_free_resp;
	}

	/* Wait for task to finish */
	while (t_pfr.state != TASK_ISCOMPLETE) {
		error = tsleep(resp, PCATCH | PWAIT, "pfexecve_conn",  0);
		if (error) {
			task_del(tq, &k_task);
			taskq_destroy(tq);
			goto bad_free_resp;
		}
	}

	/* Release task resources */
	taskq_destroy(tq);

	if (t_pfr.error) {
		/*
		 * t_pfr.error is set to ENOTCONN
		 * for all errors except socreate
		 */
		error = t_pfr.error;
		goto bad_free_resp;
	}

	/* Error with tx/rx to pfexecd */
	if ((error = transceive_pfexecd(&t_pfr)))
		goto bad_free_resp;

	/* No receive errors, we can parse daemon response */
	if ((error = resp->pfr_errno) != 0) {
		goto bad_free_resp;
	}

	/* 4. Validate Response and Extract data */

	/* Parse the resp packet */
	if ((error = parse_response(resp)))
		goto bad_free_resp;

	/* Unpack envp */
	new_env = build_new_env(resp);

	if (new_env == NULL) {
		error = EINVAL;
		goto bad_free_env;
	}

	/* Check that chroot path exists if required, pre exec */
	if ((resp->pfr_flags & PFRESP_CHROOT) &&
	    (error = lookup_chroot_path(p, resp)))
		goto bad_free_env;

	/* 5. Apply user credential changes to process */
	if ((error = set_creds_check(resp)))
		goto  bad_free_env;

	/*
	 * Copy credentials and update process ucred with newcred
	 */
	newcred = crget();
	crset(newcred, cred);
	crhold(cred);			/* Hold for fallback */
	newcred->cr_uid = resp->pfr_uid;
	newcred->cr_ruid = resp->pfr_uid;
	newcred->cr_gid = resp->pfr_gid;
	newcred->cr_rgid = resp->pfr_gid;

	/* Set group memberships if requested */
	if (resp->pfr_flags & PFRESP_GROUPS) {
		if (resp->pfr_ngroups == 0) {
			bzero(newcred->cr_groups, sizeof(gid_t)
			    * newcred->cr_ngroups);
			newcred->cr_ngroups = 0;
		} else {
			memcpy(newcred->cr_groups, resp->pfr_groups,
			    sizeof(gid_t) * resp->pfr_ngroups);
			newcred->cr_ngroups = resp->pfr_ngroups;
		}
	}

	/* Change Creds */
	pr->ps_ucred = newcred;
	atomic_setbits_int(&pr->ps_flags, PS_SUGID);
	chgproccnt(cred->cr_uid, -1);
	chgproccnt(resp->pfr_uid, 1);

	dorefreshcreds(pr, p);

	/*
	 * 6. Exec, exec will release stopped threads
	 */
	SCARG(&args, path) = SCARG(uap, path);
	SCARG(&args, argp) = SCARG(uap, argp);
	SCARG(&args, envp) = new_env;

	error = sys_execve_from_pfexec(p, (void *)&args, retVal);

	free_env(new_env, resp);

	if (error) {
		/* exec failed, must revert permissions and undo proccnt */
		pr->ps_ucred = cred;
		chgproccnt(newcred->cr_uid, -1);
		chgproccnt(cred->cr_uid, 1);
		dorefreshcreds(pr, p);
		crfree(newcred);
		goto bad_free_resp;
	}

	/* No longer requires a ref to old creds */
	crfree(cred);

	/* 7. Apply chroot change (if any) */
	if (resp->pfr_flags & PFRESP_CHROOT) {
		if ((error = dochroot_tings(p, resp)) != 0) {
			goto bad_free_resp;
		}
	}

	/* 8. Clean up */
	free(resp, M_EXEC, sizeof(struct pfexec_resp));
	free(req, M_EXEC, sizeof(struct pfexec_req));
	vrele(vp);
	return (0);

	/* Bad Exits release alloced resources this run... */
bad_free_env:
	free_env(new_env, resp);
bad_free_resp:
	free(resp, M_EXEC, sizeof(struct pfexec_resp));
bad_free_req:
	free(req, M_EXEC, sizeof(struct pfexec_req));
	vrele(vp);
	return (error);
release:
	free(argp, M_EXEC, NCARGS);
	free(req, M_EXEC, sizeof(struct pfexec_req));
	vrele(vp);
	return (error);
}

/*
 * Free internal environment array
 */
void
free_env(char **new_env, struct pfexec_resp *resp)
{
	int i;
	for (i = 0; new_env[i] != NULL; ++i) {
		free(new_env[i], M_EXEC, sizeof(char *)
		    * resp->pfr_envp[i].pfa_len + 1);
	}
	free(new_env, M_EXEC, sizeof(char **) *  resp->pfr_envc + 1);
}

/*
 * Create an env array for resp and return a pointer to it.
 * 	array is terminated with NULL, and can be used to free it upto that.
 */
char **
build_new_env(struct pfexec_resp *resp)
{
	int i;
	char **new_env = malloc(sizeof(char *) * resp->pfr_envc + 1,
	    M_EXEC, M_WAITOK | M_ZERO);

	for (i = 0; i < resp->pfr_envc; ++i)  {
		if (resp->pfr_envp[i].pfa_offset > ARG_MAX ||
		    resp->pfr_envp[i].pfa_len > ARG_MAX) {
			new_env[i] = NULL;
			goto free_env;
		}

		new_env[i] = malloc(sizeof(char *) *
		    resp->pfr_envp[i].pfa_len + 1,
		    M_EXEC, M_WAITOK | M_ZERO);

		strncpy(new_env[i], resp->pfr_envarea +
		    resp->pfr_envp[i].pfa_offset,
		    resp->pfr_envp[i].pfa_len);
	}
	/* Used for freeing later */
	new_env[i] = NULL;		/* Indicate End of data */
	return new_env;			/* Must be freed by caller */
free_env:
	for (i = 0; new_env[i] != NULL; ++i) {
		free(new_env[i], M_EXEC, sizeof(char *)
		    * resp->pfr_envp[i].pfa_len + 1);
	}
	free(new_env, M_EXEC, sizeof(char **) *  resp->pfr_envc + 1);
	return NULL;
}


/*
 * lookup path in sysspace, will release vref on success
 * dochroot_tings also does basically this, but this is used as a
 * prelim check prior to we exec.
 */
static int
lookup_chroot_path(struct proc *p, struct pfexec_resp *resp)
{
	struct nameidata ndi;
	int rc;
	struct vnode *vp;

	NDINIT(&ndi, LOOKUP, FOLLOW | LOCKLEAF,
	    UIO_SYSSPACE, resp->pfr_chroot, p);
	rc = namei(&ndi);
	if (rc != 0)
		return (rc);

	vp = ndi.ni_vp;

	/* Chroot path does not exist */
	if (vp->v_type != VDIR)
		rc = ENOTDIR;

	vp = ndi.ni_vp;

	/* Unlock node and release ref */
	vput(vp);
	return (0);
}

/*
 * Check that dir change can be applied
 */
static int
change_dir(struct nameidata *ndp, struct proc *p)
{
	struct vnode *vp;
	int error;

	if ((error = namei(ndp)) != 0)
		return (error);

	vp = ndp->ni_vp;

	if (vp->v_type != VDIR)
		error = ENOTDIR;

	if (error)
		vput(vp);
	else
		VOP_UNLOCK(vp);

	return (error);
}

/*
 * Change process root directory
 */
static int
dochroot_tings(struct proc *p, struct pfexec_resp *resp)
{
	struct vnode *old_cdir, *old_rdir;
	struct filedesc *fdp = p->p_fd;
	struct nameidata nd;
	int error = 0;

	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF,
	    UIO_SYSSPACE, resp->pfr_chroot, p);

	if ((error = change_dir(&nd, p)) != 0) {
		return error;
	}

	/* Off to jail u go */
	if (fdp->fd_rdir != NULL) {
		vref(nd.ni_vp);
		old_rdir = fdp->fd_rdir;
		old_cdir = fdp->fd_cdir;
		fdp->fd_rdir = fdp->fd_cdir = nd.ni_vp;
		vrele(old_rdir);

		if (old_cdir != NULL)
			vrele(old_cdir);
	} else {
		vref(nd.ni_vp);
		fdp->fd_rdir = nd.ni_vp;
		fdp->fd_cdir = nd.ni_vp;
	}
	return (0);
}

static int
set_creds_check(struct pfexec_resp *resp)
{
	if ((resp->pfr_flags & PFRESP_UID) &&
	    (resp->pfr_flags & PFRESP_GID))
		return (0);

	return (EINVAL);
}

/*
 * Check that a given response packet resp, is formatted correctly.
 * Should be called prior to accessing packet data.
 */
static int
parse_response(struct pfexec_resp *resp)
{
	uint32_t flags = resp->pfr_flags;
	uint32_t all_flags = PFRESP_UID | \
	    PFRESP_GID | \
	    PFRESP_GROUPS | \
	    PFRESP_CHROOT | \
	    PFRESP_ENV;

	int error = 0;

	/* Invalid Flags Set */
	if (flags & ~all_flags) {
		return EINVAL;
	}

	/* UID and GID must be within limits */
	if (flags & PFRESP_UID) {
		if (resp->pfr_uid >= UID_MAX) {
			return EINVAL;
		}
	}

	if (flags & PFRESP_GID) {
		if (resp->pfr_uid >= GID_MAX) {
			return EINVAL;
		}
	}

	if (flags & PFRESP_GROUPS) {
		if (resp->pfr_ngroups > NGROUPS_MAX) {
			return EINVAL;
		}
	}

	if (flags & PFRESP_CHROOT) {
		if (strnlen(resp->pfr_chroot, PATH_MAX) < 1 ||
		    strnlen(resp->pfr_chroot, PATH_MAX) >= PATH_MAX) {
			return (EINVAL);
		}
	}

	if (flags & PFRESP_ENV) {
		if (resp->pfr_envc >= 1024) {
			return (EINVAL);
		}

		if (strnlen(resp->pfr_envarea, ARG_MAX) < 1 ||
		    strnlen(resp->pfr_envarea, ARG_MAX) >= ARG_MAX) {
			return (EINVAL);
		}
	} else {
		/* ENVIRON must always be valid */
		return EINVAL;
	}
	return (error);
}