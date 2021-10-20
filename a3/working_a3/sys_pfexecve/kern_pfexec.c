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

void transceive_pfexecd(void *);

/* Used for debug messaging to process tty */
struct tty *tty;

const struct kmem_va_mode kv_pfexec = {
	.kv_wait = 1,
	.kv_map = &exec_map
};

struct task_transeive_pfr {
	struct pfexec_req *req;
	struct pfexec_resp *resp;
	uint32_t error;
	uint32_t state;
};

struct mbuf *
build_mbuf2(void *buf, int tot_len)
{
	struct mbuf *m;
	struct mbuf *top, **mp;
	int len = 0;

	top = NULL;
	mp = &top;

	while (tot_len > 0) {

		m = MCLGETL(NULL, M_WAIT, MAXMCLBYTES);
		m->m_flags = M_EXT | M_EOR;

		if (m == NULL || !ISSET(m->m_flags, M_EXT)) {
			ttyprintf(tty, "FAILED\n");
			m_freem(top);			//!!CHANGE FROM M to TOP
			return NULL;
		}

		len = tot_len > MAXMCLBYTES ? MAXMCLBYTES : tot_len;
		//ttyprintf(tty, "LEN: %d\n", len);
		bcopy(buf, mtod(m, void *), len);
		buf += len;
		m->m_len = len;
		tot_len -= len;

		*mp = m;
		mp = &m->m_next;
	}
	
	return (top);
}

void 
transceive_pfexecd(void *arg)
{	
	struct task_transeive_pfr *t_pfr = arg;
	struct pfexec_req *r = t_pfr->req;
	struct pfexec_resp *resp = t_pfr->resp;
	struct mbuf *nam = NULL, *mopts = NULL;
	struct sockaddr *sa;
	struct sockaddr_un addr;
	struct socket *so;
	
	
	struct mbuf *top = NULL;
	struct mbuf *recv_top;
	struct uio auio;

	int s, error = 0, recvflags = 0;
	
	t_pfr->state = TASK_PENDING;
	t_pfr->error = error;

	/* Create socket */
	if ((error = socreate(AF_UNIX, &so, SOCK_SEQPACKET, 0))) {
		ttyprintf(tty, "create err\n");
		goto close;
	}

	/* Connect to path PFEXECD_SOCK */
	bzero(&addr, sizeof(addr));
	addr.sun_len = sizeof(addr);
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, PFEXECD_SOCK, sizeof(addr.sun_path));

	MGET(nam, M_WAIT, MT_SONAME);
	nam->m_len = addr.sun_len;
	sa = mtod(nam, struct sockaddr *);
	memcpy(sa, &addr, addr.sun_len);

	/* Set input buffer size, probably not necessary */
	MGET(mopts, M_WAIT, MT_SOOPTS);

	if (mopts == NULL)
		goto close;
	
	mopts->m_len = sizeof(struct pfexec_resp) + 32;

	s = solock(so);
	error = sosetopt(so, SOL_SOCKET, SO_RCVBUF, mopts);

	if (error) {
		error = ENOTCONN;
		ttyprintf(tty,"opt err - %d\n", error);
		sounlock(so, s);
		goto close;
	}

	error = soconnect(so, nam);

	if (error)  {
		error = ENOTCONN;
		ttyprintf(tty, "conn err 1 - %d\n", error);
		sounlock(so, s);
		goto close;
	}

	while ((so->so_state & SS_ISCONNECTING) && so->so_error == 0) {
		error = tsleep(so, PWAIT | PCATCH, "wait_on_conn", so->so_timeo);
		if ((error == EINTR) || (error == ERESTART)) {
			sounlock(so, s);
			goto close;					
		}
	}

	if (so->so_error) {
		error = so->so_error;
		so->so_error = 0;
		error = ENOTCONN;
		ttyprintf(tty, "conn err 2 - %d\n", error);
		sounlock(so, s);
		goto close;
	}

	sounlock(so, s);
	
	/* Build MBUF from req packet */
	top = build_mbuf2((void *)r, sizeof(struct pfexec_req));
	
	if (top == NULL) {
		ttyprintf(tty, "MBUF BUILD FAIL:%d\n", error);
		goto close;
	}

	/* Send Message and wait..., should free top*/
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

	ttyprintf(tty, "blocking for recv...\n");

	error = soreceive(so, NULL, &auio, &recv_top, NULL, &recvflags, 0);

	if (error) {
		error = ENOTCONN;
		ttyprintf(tty, "recv error: %d\n", error);
		goto close;
	}
	
	/* Copy Daemon Response */
	m_copydata(recv_top, 0, sizeof(struct pfexec_resp), resp);
	
	ttyprintf(tty, "Resp: %d  -- %d\n", resp->pfr_flags, resp->pfr_errno);

	/* Release recv mbuf chain */
	m_freem(recv_top);

close:
	m_free(mopts);
	m_freem(nam);
	soclose(so, MSG_DONTWAIT);
	ttyprintf(tty, "ERROR VALUE:%d\n", error);
	/* Signal Completion and Error */
	t_pfr->state = TASK_ISCOMPLETE;
	t_pfr->error = error;
	wakeup(resp);
}

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

int
sys_pfexecve(struct proc *p, void *v, register_t *retVal)
{
	struct sys_pfexecve_args /*{
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

	struct process *pr = p->p_p;                   /* Should this be tested ? */
	tty = pr->ps_pgrp->pg_session->s_ttyp;			//! Debug

	struct ucred *cred = p->p_ucred;
	struct vnode *vp = NULL;
	struct pfexec_req *req;
	struct pfexec_resp *resp;
	const char *file_path;

	struct pfexecve_opts opts;
	size_t len;
	int error = 0, rc = 0, argc, envc;
	uint32_t offset;

	char *const *cpp, *dp, *sp;
	char *argp;

	struct task_transeive_pfr t_pfr;

	/* 1. Validity Checks */
	if (SCARG(uap, opts) == NULL) 
		return EINVAL;

	if ((error = copyin(SCARG(uap, opts), &opts, sizeof(struct pfexecve_opts))))
		return error;

	/* Check the path to be executed is valid */
	file_path = SCARG(uap, path);

	if (file_path == NULL)
		return ENOENT;

	error = lookup_path(file_path, p, &vp);

	if (error != 0)
		return (error);        /* vnode cannot be resolved */

	SCARG(&args, path) = SCARG(uap, path);
	SCARG(&args, argp) = SCARG(uap, argp);
	SCARG(&args, envp) = SCARG(uap, envp);

	//copyin(SCARG(uap, path), path, sizeof(path));	//! Debug Only
	//uprintf("TRYING_PATH: %s\n", path);			//! Debug Only

	/* 2. Setup request packet */
	req = malloc(sizeof(struct pfexec_req), M_EXEC, M_WAITOK | M_ZERO); 
  
	req->pfr_pid = pr->ps_pid;
	req->pfr_uid = cred->cr_uid;
	req->pfr_gid = cred->cr_gid;
	req->pfr_ngroups = cred->cr_ngroups;
	memcpy(req->pfr_groups, cred->cr_groups, req->pfr_ngroups * sizeof (gid_t));

	req->pfr_req_flags = opts.pfo_flags;

	if (opts.pfo_flags & PFEXECVE_USER) {
		if (*opts.pfo_user == '\0') {
			error = EINVAL;
			goto bad;
		}
		memcpy(req->pfr_req_user, opts.pfo_user, sizeof(char) * LOGIN_NAME_MAX);
	}

	copyin(file_path, req->pfr_path, sizeof(char) * PATH_MAX);
    
	/* GET ARGV */
	/* allocate an argument buffer */
	argp = km_alloc(NCARGS, &kv_pfexec, &kp_pageable, &kd_waitok);

	if (argp == NULL) {
		error = ENOMEM;
		goto bad_nomem;
	}

	if(!(cpp = SCARG(uap, argp))) {
		error = EFAULT;
		goto bad;
	}

	dp = argp;
	argc = 0;
	offset = 0;
   
	while (1) {
		len = argp + ARG_MAX - dp;

		if ((error = copyin(cpp, &sp, sizeof(sp))) != 0)
			goto bad;

		if (!sp)
			break;

		if ((error = copyinstr(sp, dp, len, &len)) != 0) {
			if (error == ENAMETOOLONG)
				error = E2BIG;
			goto bad;
		}

		if (argc >= 1024){ 
			error = E2BIG;
			goto bad;
		}
            
		if (offset >= ARG_MAX) {
			error = E2BIG;
			goto bad;
		}

		req->pfr_argp[argc].pfa_offset = offset;
		req->pfr_argp[argc].pfa_len = len - 1;			/* Not including NUL */
		/* Max len - current offset into buffer - ONE NUL at the end */
		rc = strlcat(req->pfr_argarea, dp, ARG_MAX - offset - 1);          

		if (rc >= (ARG_MAX - offset - 1)) {
			error = E2BIG;
			goto bad;
		}
		//uprintf("Built: %s  -- offset: %d -- len: %d  -- argc: %d\n", dp, req->pfr_argp[argc].pfa_offset, req->pfr_argp[argc].pfa_len, argc);
		offset += len - 1;								/* Not including NUL */
		dp += len;
		cpp++;
		argc++;
	}

	/* must have at least one argument */
	if (argc == 0) {
		error = EINVAL;
		goto bad;
	}

	req->pfr_argc = argc;

	//uprintf("final args:%s--\n", req->pfr_argarea);    //!DEBUG
	//uprintf("Argc: %d\n", argc);

	/* GET ENVIRON */
	envc = 0;
	offset = 0;

	if ((cpp = SCARG(uap, envp)) != NULL ) {
		while (1) {
			len = argp + ARG_MAX - dp;
			if ((error = copyin(cpp, &sp, sizeof(sp))) != 0)
				goto bad;
			if (!sp)
				break;
			if ((error = copyinstr(sp, dp, len, &len)) != 0) {
				if (error == ENAMETOOLONG)
					error = E2BIG;
				goto bad;
			}	
			
			req->pfr_envp[envc].pfa_offset = offset;
			req->pfr_envp[envc].pfa_len = len - 1;		/* No NUL in len */
			/* Max len - current offset into buffer - ONE NUL at the end */
			rc = strlcat(req->pfr_argarea, dp, ARG_MAX - offset - 1);          

			if (rc >= (ARG_MAX - offset - 1)) {
				error = E2BIG;
				goto bad;
			}
			//uprintf("Built: %s  -- offset: %d -- len: %d  -- envc: %d\n", dp, req->pfr_envp[envc].pfa_offset, req->pfr_envp[envc].pfa_len, envc);
			offset += len - 1;
			dp += len;
			cpp++;
			envc++;
		}
	} //TODO Do something with NULL ENV?

	//TODO Single Thread Only and release before we call exec
	req->pfr_envc = envc;
	//uprintf("final args:%s--\n", req->pfr_envarea);    //!DEBUG

	/* 3. pfexecd transeivce data */
	uprintf("Entering...\n");							//!DEBUG
	tq = taskq_create("conn", 1, IPL_NET, 0);
	if (tq == NULL) {
		error = EAGAIN;
		goto bad;
	}
	/* Allocate for resp struct */
	resp = malloc(sizeof(struct pfexec_resp), M_EXEC, M_WAITOK | M_ZERO); 
	bzero(&t_pfr, sizeof(struct task_transeive_pfr));
	t_pfr.req = req;
	t_pfr.resp = resp;

	task_set(&k_task, transceive_pfexecd, (void *)&t_pfr);
	error = task_add(tq, &k_task);

	if (error != 1) {
		error = EBUSY;			//Not the right error
		goto bad_0;
	}

	/* Wait for task to finish */
	while (t_pfr.state != TASK_ISCOMPLETE) {
		uprintf("Sleeping...\n");
		error = tsleep(resp, PWAIT | PCATCH, "pfexecve_conn",  0);
		if ((error == EINTR) || (error == ERESTART)) {
			goto bad_0;					
		}
	}

	uprintf("Task Complete\n");

	if (t_pfr.error) {
		/* t_pfr.error is set to ENOTCONN for all errors except socreate */
		error = t_pfr.error;
		goto bad_0;
	}

	/* No errors, we can parse daemon response */
	if ((error = resp->pfr_errno) != 0) {
		goto bad_0;
	}
	/* Parse the resp packet */

	/* 5. Apply user credential changes to process */

	/* 6. Exec */
	error = sys_execve(p, (void *)&args, retVal);

	if(error)
		goto bad_0;		//TODO CHECK THIS

	/* 7. Apply chroot change (if any) */

	/* 8. Clean up */
	//! free vnoderef
bad_0:
	free(resp, M_EXEC, sizeof(struct pfexec_resp));
bad:
	km_free(argp, NCARGS, &kv_pfexec, &kp_pageable);
bad_nomem:
	free(req, M_EXEC, sizeof(struct pfexec_req));
	return (error);
}

