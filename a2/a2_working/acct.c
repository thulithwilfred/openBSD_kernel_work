/**
 * @file acct.c 
 * @author Thulith Wilfred (thulith.mallawa@uqconnect.edu.au)
 * @brief 
 * @version 0.1
 * @date 2021-09-13
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/filio.h>
#include <sys/fcntl.h>
#include <sys/proc.h>

#include <sys/rwlock.h>
#include <sys/tty.h>

#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/resourcevar.h>

#include <sys/namei.h>
#include <sys/vnode.h>

#include <sys/tree.h>

#include "acct.h"
//TODO STYLE BRUH
/* Local Defines */
#define ALL_OFF 		0x00		/* Set audit status, all off */
#define RDWR_MODE_OK 	1 			/* Current mode is RDWR Mode */
#define RDWR_MODE_NON	0
#define FILE_ENA_MASK 	0x78		/* Bitmask to force set of file fork/exec/exit */

/* Globals 
 * The following members should be operated on atomically.
 */
int rdwr_mode = 0;					/* Is the device opened in RDWR mode */
int sequence_num = 0;				/* Current sequence number for a message */
int open_status = 0; 				/* Is the device currently opened */
int device_opened = 0;				/* Is the device currently opened */
uint32_t acct_audit_stat = ALL_OFF;	/* Starting global flags */
 

/* TailQ Data Structures */

/* 
 * The following union allows for a single message to be enqueed into the message queue (TAILQ),
 * the sender must set the type field of struct message and the receiver must read the type field of struct message to verify data types
 */
union message_data {
	struct acct_fork fork_d;
	struct acct_exec exec_d;
	struct acct_exit exit_d;
	struct acct_open open_d;
	struct acct_rename rename_d;
	struct acct_unlink unlink_d;
	struct acct_close close_d;
};


/* Message queue that holds event messages */
struct message {
	TAILQ_ENTRY(message) entries;
	int type; 						/* Defines type of data the message is, i.e struct acct_fork relates to ACCT_MSG_FORK*/
	unsigned int size; 				/* Total size of the data held by 'data' in bytes, set by sender */
	union message_data data;		/* acct message */
};

/* Red black tree that holds tracking file vnodes */
struct tree_node {
	RB_ENTRY(tree_node) tree_entry;
	struct vnode *v;				/* Holds a tracked files vnode red */
	uint32_t audit_events;			/* File enabled events */
	uint32_t audit_conds;			/* Audit conditions set for the tracking file */
};


/* Local Functions */
int resolve_vnode(const char*, struct proc *, struct vnode **);
int vnode_cmp(struct tree_node *, struct tree_node *);
int add_node_to_tree(struct vnode *, uint32_t *, uint32_t *);
void free_traversed_vnodes(struct nameidata *);


/* Initializers */
/* RW Lock */
struct rwlock rwl = RWLOCK_INITIALIZER("acct_lock");

TAILQ_HEAD(message_queue, message) head; 		

RB_HEAD(vnodetree, tree_node) rb_head = RB_INITIALIZER(&rb_head);
RB_PROTOTYPE(vnodetree, tree_node, tree_entry, vnode_cmp);
RB_GENERATE(vnodetree, tree_node, tree_entry, vnode_cmp);

/**
 * @brief Node comparison used to compare trees' nodes with each other
 * 	If the first argument is smaller than the second, the function returns a value smaller 
 * 	than zero. If they are equal, the function returns zero.
 * 
 *  Otherwise, it should return a value greater than zero.
 *  The compare function defines the order of the tree elements
 * 
 * @param v1 node 1
 * @param v2 node 2
 * @return * Node 
 */
int
vnode_cmp(struct tree_node *node1, struct tree_node *node2)
{
	return (node1->v->v_id < node2->v->v_id ? -1 : node1->v->v_id > node2->v->v_id);
}


/**
 * @brief Initialise state required for operations 
 * 
 */
int
acctattach(int num) 
{
	/* Initialise the message queue for acct messages */
	TAILQ_INIT(&head);

	/* Clear Audit Stats */
	rw_enter_write(&rwl);
	acct_audit_stat = ALL_OFF;
	sequence_num = 0;
	open_status = 0;
	rdwr_mode = 0;
	device_opened = 0;
	rw_exit_write(&rwl);

	return (0);
}

int
acctopen(dev_t dev, int flag, int mode, struct proc *p)
{
	/* Allow only 0th minor to be opened */
	if (minor(dev) != 0)
		return (ENXIO);

	if (device_opened)
		return (EBUSY);

	flag = OFLAGS(flag);

	/* If not opened exclusively */
	if ((flag & O_EXLOCK) == 0)
		return ENODEV;

	/* If not opened with O_RDONLY or O_RDWR */
	if (flag & O_WRONLY)
		return (EPERM);

	/* Set the mode in which the device was opened for, only care about if RDWR */
	if (flag & O_RDWR)
		rdwr_mode = RDWR_MODE_OK; 
	else 
		rdwr_mode = RDWR_MODE_NON;
	
	/* Reset Sequence Num */
	rw_enter_write(&rwl); /* The lock is probably not needed here? */
	sequence_num = 0;
	device_opened = 1;
	rw_exit_write(&rwl);

	return (0);
}



int 
acctread(dev_t dev, struct uio *uio, int flags)
{
	struct message *acct_msg;
	int err;

	rw_enter_read(&rwl);

	if (TAILQ_EMPTY(&head)) {
		/* Data not ready, wake me up when ready... */
		err = rwsleep(&head, &rwl, PWAIT | PCATCH ,"Waiting for events", 0);

		/* Interuppted by sys call or returning from signal */
		if ((err == EINTR) || (err == ERESTART)) {
			rw_exit_read(&rwl);
			return (err);						
		}

		/* Processes returning from sleep should always re-evaluate the conditions */
		if (TAILQ_EMPTY(&head))  {
			rw_exit_read(&rwl); 		
			return EIO;
		}
	} 

	/* Get next message from queue */
	acct_msg = TAILQ_FIRST(&head);

	err = uiomove((void*)&acct_msg->data, acct_msg->size, uio);

	if (err) {
		/* uiomove failed */
		TAILQ_REMOVE(&head, acct_msg, entries);
		free(acct_msg, M_DEVBUF, sizeof(struct message));
		rw_exit_read(&rwl);
		return (EFAULT);
	}

	/* Uiomove succeeded, clear message from queue */
	TAILQ_REMOVE(&head, acct_msg, entries);
	free(acct_msg, M_DEVBUF, sizeof(struct message));
	rw_exit_read(&rwl);
	return 0;
}

/**
 * @brief Set the audit stats 
 * 
 * @param set_mask bit fields to be set 
 */
void
set_audit_stats(uint32_t set_mask) 
{
	rw_enter_write(&rwl);
	acct_audit_stat |= set_mask;
	rw_exit_write(&rwl);

}

/**
 * @brief Clear the audit stats 
 * 
 * @param set_mask bit fields to be cleared
 */
void clear_audit_stats(uint32_t clear_mask)
{
	rw_enter_write(&rwl);
	acct_audit_stat &= ~(clear_mask);
	rw_exit_write(&rwl);
}


int 
acctioctl(dev_t dev, u_long cmd, caddr_t data, int flag, struct proc *p)
{
	struct acct_ctl *ctl;
	struct vnode *vn;
	struct message *next_msg;
	const char* pathname;


	/* Support for generic ioctl requests */
	switch(cmd) {
		case FIONREAD:
			/* Get the number of bytes that are immediately available for reading */
			rw_enter_read(&rwl);
			if (TAILQ_EMPTY(&head)) {
				*(int *)data = 0; 					/* Queue is empty, nothing to read */
			} else {
				next_msg = TAILQ_FIRST(&head); 		/* Next available message FIFO */
				*(int *)data = next_msg->size;
			}
			rw_exit_read(&rwl);
			return (0);
		case FIONBIO:
			/*  Handled in the upper FS layer */
			if (*(int *)data != 0) 					/* Attempting to set non-blocking, miss me with that... */
				return (EOPNOTSUPP);
		case FIOASYNC:
			return (EOPNOTSUPP);
	}

	/* Device specific ioctls not accepted in read only mode */
	if (rdwr_mode != RDWR_MODE_OK) 
	 	return (ENOTTY); 

	ctl = (struct acct_ctl*)data;

	/* Support for device specific ioctl requests */
	switch(cmd) {
		case ACCT_IOC_STATUS:
			rw_enter_read(&rwl);
			ctl->acct_ena = acct_audit_stat;		/* update with currently enabled features */
			ctl->acct_fcount = 77;					//TODO	/* update count of files */
			rw_exit_read(&rwl);
			break;
		case ACCT_IOC_FSTATUS:
			break;
		case ACCT_IOC_ENABLE:		
			set_audit_stats(ctl->acct_ena);			/* set features to enable */

			rw_enter_read(&rwl);
			ctl->acct_ena = acct_audit_stat;		/* update with currently enabled features */
			rw_exit_read(&rwl);
			break;
		case ACCT_IOC_DISABLE:
			clear_audit_stats(ctl->acct_ena);		/* set features to disable */

			rw_enter_read(&rwl);
			ctl->acct_ena = acct_audit_stat;		/* update with currently enabled features  */
			rw_exit_read(&rwl);
			break;
		case ACCT_IOC_TRACK_FILE:
			/* 1 Resolve vnode from path */
			rw_enter_read(&rwl);
			pathname = ctl->acct_path;
			ctl->acct_ena &= FILE_ENA_MASK;			/* Disable fork/exec/exit */
			
			if (resolve_vnode(pathname, p, &vn) != 0) {
				rw_exit_read(&rwl);
				return ENOENT;						/* Unable to resolve */
			}

			/* 
			 * 2 Vnode resolved, add to tracked tree
			 * 	 If file is already tracked, params are updated.
			 */
			if (add_node_to_tree(vn, &ctl->acct_cond, &ctl->acct_ena) == EEXIST) {
				rw_exit_read(&rwl);
				return (0);
			}
	
			rw_exit_read(&rwl);
			break;
		case ACCT_IOC_UNTRACK_FILE:
			break;
		default:
			/* Inappropriate ioctl for device */
			return (ENOTTY);
	}
	return (0);
}


int
add_node_to_tree(struct vnode *vn, uint32_t *ctl_conds, uint32_t *ctl_events)
{
	struct tree_node *new_node, *res; 

	/* Copy ref to vnode and update set up file events/conds */
	new_node = malloc(sizeof(struct tree_node),  M_DEVBUF, M_WAITOK | M_ZERO);
	new_node->v = vn;
	new_node->audit_conds = *ctl_conds;
	new_node->audit_events = *ctl_events;

	/* Try add Vnode to tracked tree of vnodes, checks by v_id */
	res = RB_INSERT(vnodetree, &rb_head, new_node);
	
	if (res != NULL) {
		/* Matching element exists in tree */
		uprintf("Already in tree....\n");
		res->audit_conds |= *ctl_conds;	
		res->audit_events |= *ctl_events;

		/* Update ctl params with existing ones */
		*ctl_conds = res->audit_conds;
		*ctl_events = res->audit_events;

		free(new_node, M_DEVBUF, sizeof(struct tree_node));
		return EEXIST;
	}

	/* Added new entry */
	return (0);
}

int 
resolve_vnode(const char* u_pathname, struct proc *p, struct vnode **vn)
{
	struct nameidata nd;
	char* k_pathname;
	int err = 0;

	k_pathname = malloc(PATH_MAX, M_DEVBUF, M_WAITOK | M_ZERO);

	memcpy(k_pathname, u_pathname, PATH_MAX);

	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF,
    	UIO_SYSSPACE, k_pathname, p);

	if ((err = namei(&nd)) != 0) {
		free_traversed_vnodes(&nd);
		free(k_pathname, M_DEVBUF, PATH_MAX);
		return err;
	}

	/* Copy ref to resolved vnode */
	*vn = nd.ni_vp;
	
    /* release lock from namei, but keep ref to vnode */
	if (nd.ni_vp)
		VOP_UNLOCK(nd.ni_vp);

	free(k_pathname, M_DEVBUF, PATH_MAX);
	return (err);
}

/**
 * @brief Refer to unveil_free_traversed_vnodes
 * 
 * @param ndp 
 */
void 
free_traversed_vnodes(struct nameidata *ndp) 
{
	if (ndp->ni_tvpsize) {
		size_t i;
		
		for (i = 0; i < ndp->ni_tvpend; i++)
			vrele(ndp->ni_tvp[i]); /* ref for being in list */
			
		free(ndp->ni_tvp, M_PROC, ndp->ni_tvpsize *sizeof(struct vnode *));
        ndp->ni_tvpsize = 0;
        ndp->ni_tvpend = 0;
	}
}


struct acct_common 
construct_common(struct process *pdata, int type)
{
	struct timespec uptime, booted;
	struct acct_common common;

	/* 
	 * Create message common fields 
	 */

	/* Sequence begins from index 0 */
	common.ac_seq = sequence_num;
	sequence_num++;

	/* Set message type and data size */
	switch (type) {
		case ACCT_MSG_FORK:
			common.ac_type = ACCT_MSG_FORK;	
			common.ac_len = sizeof(struct acct_fork);
			break;
		case ACCT_MSG_EXEC:
			common.ac_type = ACCT_MSG_EXEC;
			common.ac_len = sizeof(struct acct_exec);			
			break;
		case ACCT_MSG_EXIT:
			common.ac_type = ACCT_MSG_EXIT;	
			common.ac_len = sizeof(struct acct_exit);		
			break;
		case ACCT_MSG_OPEN:
			break;
		case ACCT_MSG_RENAME:
			break;
		case ACCT_MSG_UNLINK:
			break;
		case ACCT_MSG_CLOSE:
			break;
	}

	/*  Get command name */
	memcpy(common.ac_comm, pdata->ps_comm, sizeof(common.ac_comm));

	/* Get Time */
	nanouptime(&uptime);
	nanoboottime(&booted);
	timespecadd(&booted, &pdata->ps_start, &common.ac_btime);	/* Calculate and update start time */	
	timespecsub(&uptime, &pdata->ps_start, &common.ac_etime); 	/* Calculate and update elapsed time*/


	/* Get Ids */
	common.ac_pid = pdata->ps_ppid;								
	common.ac_uid = pdata->ps_ucred->cr_uid;
	common.ac_gid = pdata->ps_ucred->cr_gid;

	/* Get Controlling TTY */
	if ((pdata->ps_flags & PS_CONTROLT) && 
		pdata->ps_pgrp->pg_session->s_ttyp)
			common.ac_tty = pdata->ps_pgrp->pg_session->s_ttyp->t_dev;
		else 
			common.ac_tty = NODEV;


	/* Get Accounting flags */
	common.ac_flag = pdata->ps_acflag;

	return common;
}

void
acct_fork(struct process *pr) 
{
	struct message *acct_msg;

	/* if fork accounting not enabled or device closed, let's not worry about this... */
	rw_enter_read(&rwl);
	if(device_opened == 0) {
		rw_exit_read(&rwl);
		return;
	}

	if((acct_audit_stat & ACCT_ENA_FORK) == 0) {
		rw_exit_read(&rwl);
		return;
	}
	
	rw_exit_read(&rwl);

	/* Commited to processing the message now... */
	acct_msg = malloc(sizeof(struct message), M_DEVBUF, M_WAITOK | M_ZERO); 
	
	/* Set internal message data */
	acct_msg->type = ACCT_MSG_FORK;
	acct_msg->size = sizeof(struct acct_fork);

	/* Update message common fields within this message */
	rw_enter_read(&rwl);
	/* Common message based on parent info */
	acct_msg->data.fork_d.ac_common = construct_common(pr->ps_pptr, ACCT_MSG_FORK);	
	/* Set child pid */
	acct_msg->data.fork_d.ac_cpid = pr->ps_pid;		/* Child process id */
	rw_exit_read(&rwl);

	/* Enqueue Data */
	rw_enter_write(&rwl);
	TAILQ_INSERT_TAIL(&head, acct_msg, entries);
	rw_exit_write(&rwl);

	/* Wake up read, incase it was blocked */
	wakeup(&head);
} 

void
acct_exec(struct process *pr)
{
	struct message *acct_msg;

	/* if fork accounting not enabled or device closed, let's not worry about this... */
	rw_enter_read(&rwl);
	
	if(device_opened == 0) {
		rw_exit_read(&rwl);
		return;
	}

	if((acct_audit_stat & ACCT_ENA_EXEC) == 0) {
		rw_exit_read(&rwl);
		return;
	}

	rw_exit_read(&rwl);

	/* Commited to processing the message now... */
	acct_msg = malloc(sizeof(struct message), M_DEVBUF, M_WAITOK | M_ZERO);

	/* Set internal message data */
	acct_msg->type = ACCT_MSG_EXEC;
	acct_msg->size = sizeof(struct acct_exec);

	/* Update message common fields within this message */
	rw_enter_read(&rwl);
	acct_msg->data.exec_d.ac_common = construct_common(pr, ACCT_MSG_EXEC);
	rw_exit_read(&rwl);

	/* Enqueue Data */
	rw_enter_write(&rwl);
	TAILQ_INSERT_TAIL(&head, acct_msg, entries);
	rw_exit_write(&rwl);

	/* Wake up read, incase it was blocked */
	wakeup(&head);
}

void
acct_exit(struct process *pr)
{
	struct timespec ut, st, tmp;
	struct message *acct_msg;
	struct rusage *r;
	int t;

	/* if exit accounting not enabled or device closed, let's not worry about this... */
	rw_enter_read(&rwl);

	if(device_opened == 0) {
		rw_exit_read(&rwl);
		return;
	}

	if((acct_audit_stat & ACCT_ENA_EXIT) == 0) {
		rw_exit_read(&rwl);
		return;
	}

	rw_exit_read(&rwl);

	/* Commited to processing the message now... */
	acct_msg = malloc(sizeof(struct message), M_DEVBUF, M_WAITOK | M_ZERO);
	
	/* Set internal message data */
	acct_msg->type = ACCT_MSG_EXIT;
	acct_msg->size = sizeof(struct acct_exit);

	/* Update message common fields within this message */
	rw_enter_read(&rwl);
	acct_msg->data.exit_d.ac_common = construct_common(pr, ACCT_MSG_EXIT);;

	/* 
	 * Set exit struct additional data 
	 */
	
	/* User & sys Time */
	calctsru(&pr->ps_tu, &ut, &st, NULL);
	acct_msg->data.exit_d.ac_utime = ut;
	acct_msg->data.exit_d.ac_stime = st;

	/* Avg memory usage */
	r = &pr->ps_mainproc->p_ru;								//TODO CHECK? /* ps_mainproc (struct proc) contains the  usage  details (?) */
	timespecadd(&ut, &st, &tmp);
	t = tmp.tv_sec * hz + tmp.tv_nsec / (1000 * tick); 		/* hz and tick are sys externs */

	if (t)
		acct_msg->data.exit_d.ac_mem = (r->ru_ixrss + r->ru_idrss + r->ru_isrss) / t;
    else
		acct_msg->data.exit_d.ac_mem = 0;


	/* I/O ops count */
	acct_msg->data.exit_d.ac_io = r->ru_inblock + r->ru_oublock;
	rw_exit_read(&rwl);

	/* Enqueue Data */
	rw_enter_write(&rwl);
	TAILQ_INSERT_TAIL(&head, acct_msg, entries);
	rw_exit_write(&rwl);

	/* Wake up read, incase it was blocked */
	wakeup(&head);
}


int
acctclose(dev_t dev, int flag, int mode, struct proc *p)
{
	//TODO Wipe list of unread...

	rw_enter_write(&rwl); 
	sequence_num = 0;
	device_opened = 0;
	rw_exit_write(&rwl);

	return 0;
}


int
acctwrite(dev_t dev, struct uio *uio, int flags)
{
	return EOPNOTSUPP;	
}


int 
acctpoll(dev_t dev, int events, struct proc *p)
{
	return POLLERR;
}

int
acctkqfilter(dev_t dev, struct knote *kn)
{
	return EOPNOTSUPP;
}


