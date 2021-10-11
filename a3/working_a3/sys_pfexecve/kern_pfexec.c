/*
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
* @(#)kern_pfexec.c 0.1 (UQ) - Wilfred MK
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

        char path[128];
        struct pfexecve_opts opts;
        int err;

        if (SCARG(uap, opts) == NULL) 
            return EINVAL;
    
        if ((err = copyin(SCARG(uap, opts), &opts, sizeof(struct pfexecve_opts))))
            return err;

        
        
        SCARG(&args, path) = SCARG(uap, path);
        SCARG(&args, argp) = SCARG(uap, argp);
        SCARG(&args, envp) = SCARG(uap, envp);


        copyin(SCARG(uap, path), path, sizeof(path));
        uprintf("PATH IS: %s\n", path);

        sys_execve(p, (void *)&args, retVal);
        uprintf("DID IT \n");

        /* Resolve pfexecve logic based on opts.pfo_flags */
        if (opts.pfo_flags & PFEXECVE_USER) {
            /* Use user privs and not root */

            if (*opts.pfo_user == '\0')
                return EINVAL;
            
            /* Resolve User Privs */

        }

        if (opts.pfo_flags & PFEXECVE_NOPROMPT) {
            /* Don't prompt pws */
            
        }
        return (0);
}

