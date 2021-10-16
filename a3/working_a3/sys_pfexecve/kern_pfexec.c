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

const struct kmem_va_mode kv_pfexec = {
	.kv_wait = 1,
	.kv_map = &exec_map
};


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


	struct process *pr = p->p_p;                   /* Should this be tested ? */
	struct ucred *cred = p->p_ucred;
	struct vnode *vp = NULL;
	struct pfexec_req *req;
	const char *file_path;

	struct pfexecve_opts opts;
	size_t len;
	int error = 0, rc = 0, argc;
	uint32_t offset;

	char *const *cpp, *dp, *sp;
	char *argp;

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
	if(!(cpp = SCARG(uap, argp))) {
		return EFAULT;
	}

	/* allocate an argument buffer */
	argp = km_alloc(NCARGS, &kv_pfexec, &kp_pageable, &kd_waitok);
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
		req->pfr_argp[argc].pfa_len = len - 1;				/* Not including NUL */
		/* Max len - current offset into buffer - ONE NUL at the end */
		rc = strlcat(req->pfr_argarea, dp, ARG_MAX - offset - 1);          

		if (rc >= (ARG_MAX - offset - 1)) {
			error = E2BIG;
			goto bad;
		}

		uprintf("Built: %s  -- offset: %d -- len: %d  -- argc: %d\n", dp, req->pfr_argp[argc].pfa_offset, req->pfr_argp[argc].pfa_len, argc);
		offset += len - 1;									/* Not including NUL */
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

	uprintf("final:%s--\n", req->pfr_argarea);    //!DEBUG
	//uprintf("Argc: %d\n", argc);

	/* GET ENVIRON */

	/* 3. Socket to pdfexecd and send request */

	/* 4. Wait response from daemon */

	/* 5. Apply user credential changes to process */

	/* 6. Exec */
	error = sys_execve(p, (void *)&args, retVal);

	/* 7. Apply chroot change (if any) */

	/* 8. Clean up */
	//! free vnoderef
bad:
	km_free(argp, NCARGS, &kv_pfexec, &kp_pageable);
	free(req, M_EXEC, sizeof(struct pfexec_req));
	return (error);
}

