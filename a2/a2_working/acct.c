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
int fcount = 0;						/* Tracked file count */
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
	char path[PATH_MAX];			/* Holds path */
	uint32_t audit_events;			/* File enabled events */
	uint32_t audit_conds;			/* Audit conditions set for the tracking file */
};


/* Local Functions */
int resolve_vnode(const char*, struct proc *, struct vnode **);
int vnode_cmp(struct tree_node *, struct tree_node *);
int add_node_to_tree(struct vnode *, uint32_t *, uint32_t *, const char *);
void free_traversed_vnodes(struct nameidata *);
int untrack_from_tree(struct vnode *, uint32_t *, uint32_t *);
int drop_all_files(void);
int update_from_tree(struct vnode *, uint32_t *, uint32_t *);
bool acct_this_message(uint32_t, uint32_t, int);
bool acct_conds_ok(uint32_t, uint32_t);
bool acct_mode_ok(uint32_t, int);

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
	fcount = 0;	
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

	/* Processes returning from sleep should always re-evaluate the conditions */
	if (TAILQ_EMPTY(&head))  {
		rw_exit_read(&rwl); 		
		return EIO;
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
	acct_audit_stat |= set_mask;
}

/**
 * @brief Clear the audit stats 
 * 
 * @param set_mask bit fields to be cleared
 */
void clear_audit_stats(uint32_t clear_mask)
{
	acct_audit_stat &= ~(clear_mask);
}

//TODO increment file count
int 
acctioctl(dev_t dev, u_long cmd, caddr_t data, int flag, struct proc *p)
{
	struct acct_ctl *ctl;
	struct vnode *vn;
	struct message *next_msg;
	const char* pathname;
	uint32_t file_ena_mask;


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
			ctl->acct_fcount = fcount;					
			rw_exit_read(&rwl);
			break;
		case ACCT_IOC_FSTATUS:
			rw_enter_read(&rwl);
			pathname = ctl->acct_path;

			/* 1 Resolve vnode from path */
			if (resolve_vnode(pathname, p, &vn) != 0) {
				rw_exit_read(&rwl);
				return ENOENT;						/* Unable to resolve */
			}

			if ((update_from_tree(vn, &ctl->acct_cond, &ctl->acct_ena) == ENOENT)){
				rw_exit_read(&rwl);
				return ENOENT;
			}

			rw_exit_read(&rwl);
			break;
		case ACCT_IOC_ENABLE:	
			rw_enter_read(&rwl);	
			set_audit_stats(ctl->acct_ena);			/* set features to enable */
			ctl->acct_ena = acct_audit_stat;		/* update with currently enabled features */
			rw_exit_read(&rwl);
			break;
		case ACCT_IOC_DISABLE:
			rw_enter_read(&rwl);
			clear_audit_stats(ctl->acct_ena);		/* set features to disable */
			ctl->acct_ena = acct_audit_stat;		/* update with currently enabled features  */

			file_ena_mask = (ACCT_ENA_OPEN | ACCT_ENA_CLOSE | ACCT_ENA_RENAME | ACCT_ENA_UNLINK);

			if ((acct_audit_stat & (file_ena_mask)) == 0) {
				/* Drop all files */
				uprintf("Dropping all files...\n");
				drop_all_files();
			}

			rw_exit_read(&rwl);
			break;
		case ACCT_IOC_TRACK_FILE:	
			rw_enter_read(&rwl);
			pathname = ctl->acct_path;
			ctl->acct_ena &= FILE_ENA_MASK;			/* Disable fork/exec/exit */
			/* 1 Resolve vnode from path */
			if (resolve_vnode(pathname, p, &vn) != 0) {
				rw_exit_read(&rwl);
				return ENOENT;						/* Unable to resolve */
			}

			/* 
			 * 2 Vnode resolved, add to tracked tree
			 * 	 If file is already tracked, params are updated.
			 */
			if (add_node_to_tree(vn, &ctl->acct_cond, &ctl->acct_ena, pathname) == EEXIST) {
				rw_exit_read(&rwl);
				return (0);
			}
	
			rw_exit_read(&rwl);
			break;
		case ACCT_IOC_UNTRACK_FILE:
			rw_enter_read(&rwl);
			pathname = ctl->acct_path;
			ctl->acct_ena &= FILE_ENA_MASK;			/* Disable fork/exec/exit */

			/* 1 Resolve vnode from path */
			if (resolve_vnode(pathname, p, &vn) != 0) {
				rw_exit_read(&rwl);
				return ENOENT;						/* Unable to resolve */
			}

			/* 2 Attempt to untrack */
			if (untrack_from_tree(vn, &ctl->acct_cond, &ctl->acct_ena) == ENOENT) {
				rw_exit_read(&rwl);
				return (ENOENT);					/* Not tracked */
			}

			rw_exit_read(&rwl);
			break;
		default:
			return (ENOTTY); 						/* Inappropriate ioctl for device */
	}
	return (0);
}

int 
update_from_tree(struct vnode *vn, uint32_t *ctl_conds, uint32_t *ctl_events) 
{
	struct tree_node *find_node, *res;

	/* Copy ref to vnode and update set up file events/conds */
	find_node = malloc(sizeof(struct tree_node),  M_DEVBUF, M_WAITOK | M_ZERO);
	find_node->v = vn;

	/* Test for matching v_id in tree */
	res = RB_FIND(vnodetree, &rb_head, find_node);

	free(find_node, M_DEVBUF, sizeof(struct tree_node));

	if (res == NULL) {
		/* File not tracked */
		uprintf("File not tracked...\n");
		return (ENOENT);
	}

	/* Return remaining conditions */
	uprintf("Getting file conditions...\n");
	*ctl_conds = res->audit_conds;
	*ctl_events = res->audit_events;

	return (0);
}

int
drop_all_files(void) {
	struct tree_node *res, *next;

	RB_FOREACH_SAFE(res, vnodetree, &rb_head, next) {
		/* Release ref to vnode */
		vrele(res->v);
		RB_REMOVE(vnodetree,  &rb_head, res);
		free(res, M_DEVBUF, sizeof(struct tree_node));
		fcount--;					//TODO Should set 0?
	}
	return (0);
}

int
untrack_from_tree(struct vnode *vn, uint32_t *ctl_conds, uint32_t *ctl_events)
{
	struct tree_node *find_node, *res;

	/* Copy ref to vnode and update set up file events/conds */
	find_node = malloc(sizeof(struct tree_node),  M_DEVBUF, M_WAITOK | M_ZERO);
	find_node->v = vn;

	/* Test for matching v_id in tree */
	res = RB_FIND(vnodetree, &rb_head, find_node);

	free(find_node, M_DEVBUF, sizeof(struct tree_node));

	if (res == NULL) {
		/* File not tracked */
		uprintf("File not tracked...\n");
		return (ENOENT);
	}

	/* Found a match, unset required params */
	res->audit_conds &= ~(*ctl_conds);
	res->audit_events &= ~(*ctl_events);

	if ((res->audit_conds == 0) || (res->audit_events == 0)) {
		/* Untrack file entirely */
		uprintf("Untracking...\n");
		*ctl_conds = 0;
		*ctl_events = 0;
		fcount--;	

		/* Release ref to vnode */
		vrele(res->v);
		RB_REMOVE(vnodetree,  &rb_head, res);
		free(res, M_DEVBUF, sizeof(struct tree_node));
		return(0);
	}

	/* Return remaining conditions */
	uprintf("Returning remaining conditions..\n");
	*ctl_conds = res->audit_conds;
	*ctl_events = res->audit_events;
	
	return (0);
}

int
add_node_to_tree(struct vnode *vn, uint32_t *ctl_conds, uint32_t *ctl_events, const char* pathname)
{
	struct tree_node *new_node, *res; 

	/* Copy ref to vnode and update set up file events/conds */
	new_node = malloc(sizeof(struct tree_node),  M_DEVBUF, M_WAITOK | M_ZERO);
	new_node->v = vn;
	new_node->audit_conds = *ctl_conds;
	new_node->audit_events = *ctl_events;
	
	/* Save path */
	memcpy(new_node->path, pathname, PATH_MAX);

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
	fcount++;	
	return (0);
}

int 
resolve_vnode(const char* u_pathname, struct proc *p, struct vnode **vn)
{
	//TODO cleanup this area
	struct nameidata nd;
	//char* k_pathname;
	int err = 0;

	//k_pathname = malloc(PATH_MAX, M_DEVBUF, M_WAITOK | M_ZERO);

	//memcpy(k_pathname, u_pathname, PATH_MAX);

	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF,
    	UIO_SYSSPACE, u_pathname, p);

	if ((err = namei(&nd)) != 0) {
		free_traversed_vnodes(&nd);
		//free(k_pathname, M_DEVBUF, PATH_MAX);
		return err;
	}

	/* Copy ref to resolved vnode */
	*vn = nd.ni_vp;
	
    /* release lock from namei, but keep ref to vnode */
	if (nd.ni_vp)
		VOP_UNLOCK(nd.ni_vp);

	//free(k_pathname, M_DEVBUF, PATH_MAX);
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
			common.ac_type = ACCT_MSG_OPEN;	
			common.ac_len = sizeof(struct acct_open);	
			break;
		case ACCT_MSG_RENAME:
			common.ac_type = ACCT_MSG_RENAME;	
			common.ac_len = sizeof(struct acct_rename);		
			break;
		case ACCT_MSG_UNLINK:
			common.ac_type = ACCT_MSG_UNLINK;	
			common.ac_len = sizeof(struct acct_unlink);	
			break;
		case ACCT_MSG_CLOSE:
			common.ac_type = ACCT_MSG_CLOSE;	
			common.ac_len = sizeof(struct acct_close);	
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
	acct_msg->data.exit_d.ac_common = construct_common(pr, ACCT_MSG_EXIT);

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


void
acct_close(struct process *pr, struct vnode *vn_cmp, u_int f_flag) 
{
	struct message *acct_msg;
	struct tree_node *find_node, *res;
	u_int o_flags = OFLAGS(f_flag);
	uint32_t f_events, f_conds;			/* File Unique events */
	
	/* Device not opened, no need to queue anything */
	rw_enter_read(&rwl);

	if (device_opened == 0) {
		rw_exit_read(&rwl);
		return;
	}

	/* If open accounting disabled, we outchea ... */ 
	if ((acct_audit_stat & ACCT_ENA_CLOSE) == 0) {
		rw_exit_read(&rwl);
		return;		
	}

	/* Incase a vnode wasn't resolved */
	if(vn_cmp == NULL) {
		rw_exit_read(&rwl);
		return;						
	}

	/* This file currently tracked ? */
	find_node = malloc(sizeof(struct tree_node),  M_DEVBUF, M_WAITOK | M_ZERO);
	find_node->v = vn_cmp;

	/* Test for matching v_id in tree */
	res = RB_FIND(vnodetree, &rb_head, find_node);

	free(find_node, M_DEVBUF, sizeof(struct tree_node));

	if (res == NULL) {
		rw_exit_read(&rwl);
		return;  			/* We aren't tracking this */
	}

	/* File conditions match the open call? */
	f_events = res->audit_events;
	f_conds = res->audit_conds;

	/* File doesn't have close accounting set */
	if ((f_events & ACCT_ENA_CLOSE) == 0) {
		rw_exit_read(&rwl);
		return;
	}

    uprintf("fflags %d, oflags %d\n", f_flag, o_flags);
	if (acct_conds_ok(f_conds, o_flags) == false) {
		rw_exit_read(&rwl);	 //TODO Check These
		return;				/* Condition mismatch */
	}

	/* Construct message */
	uprintf("Conds Valid\n");

	/* Commited to processing the message now... */
	acct_msg = malloc(sizeof(struct message), M_DEVBUF, M_WAITOK | M_ZERO);

	/* Set internal message data */
	acct_msg->type = ACCT_MSG_CLOSE;
	acct_msg->size = sizeof(struct acct_close);

	/* Update message common fields within this message */
	acct_msg->data.close_d.ac_common = construct_common(pr, ACCT_MSG_CLOSE);

	/* Update Open message specific fields */
	memcpy(acct_msg->data.close_d.ac_path, res->path, PATH_MAX);

	/* Add to queue */
	TAILQ_INSERT_TAIL(&head, acct_msg, entries);
	rw_exit_read(&rwl);

	/* Wake up read, incase it was blocked */
	wakeup(&head);
	return;
}

void
remove_from_tree(struct tree_node *res)
{
	/* Release ref to vnode */
	vrele(res->v);
	RB_REMOVE(vnodetree,  &rb_head, res);
	free(res, M_DEVBUF, sizeof(struct tree_node));
}


void 
acct_unlink(struct process *pr, struct vnode *vn_cmp, int err)
{
	struct message *acct_msg;
	struct tree_node *find_node, *res;
	uint32_t f_events, f_conds;			/* File Unique events */

	/* Device not opened, no need to queue anything */
	rw_enter_read(&rwl);

	/* Avert bamboozle */
	if(vn_cmp == NULL) {
		rw_exit_read(&rwl);
		return;						
	}

	/* This file currently tracked ? */
	find_node = malloc(sizeof(struct tree_node),  M_DEVBUF, M_WAITOK | M_ZERO);
	find_node->v = vn_cmp;

	/* Test for matching v_id in tree */
	res = RB_FIND(vnodetree, &rb_head, find_node);

	free(find_node, M_DEVBUF, sizeof(struct tree_node));

	if (res == NULL) {
		rw_exit_read(&rwl);
		return;  			/* We aren't tracking this */
	}

	/* At this point the file is tracked, so drop it before we return */
	fcount--;

	/* Unlink acct globally disabled */
	if ((acct_audit_stat & ACCT_ENA_UNLINK) == 0) {	
		remove_from_tree(res);
		rw_exit_read(&rwl);
		return;		
	}

	/* Device not opened, no need to queue anything */
	if (device_opened == 0) {
		remove_from_tree(res);
		rw_exit_read(&rwl);
		return;
	}

	/* File conditions match the open call? */
	f_events = res->audit_events;
	f_conds = res->audit_conds;

	/* File doesn't have unlink accounting set */
	if ((f_events & ACCT_ENA_UNLINK) == 0) {
		remove_from_tree(res);
		rw_exit_read(&rwl);
		return;
	}

	if (acct_mode_ok(f_conds, err) == false) {
		remove_from_tree(res);
		rw_exit_read(&rwl);	 //TODO Check These
		return;				/* Succes/Failure condition mismatch */
	}

	/* Construct message */
	
	/* Commited to processing the message now... */
	acct_msg = malloc(sizeof(struct message), M_DEVBUF, M_WAITOK | M_ZERO);

	/* Set internal message data */
	acct_msg->type = ACCT_MSG_UNLINK;
	acct_msg->size = sizeof(struct acct_unlink);

	/* Update message common fields within this message */
	acct_msg->data.unlink_d.ac_common = construct_common(pr, ACCT_MSG_UNLINK);

	/* Update Rename message specific fields */
	memcpy(acct_msg->data.unlink_d.ac_path, res->path, PATH_MAX);
	acct_msg->data.unlink_d.ac_errno = err;

	/* Add to queue */
	TAILQ_INSERT_TAIL(&head, acct_msg, entries);
	remove_from_tree(res);			/* Removing since unlink event */
	rw_exit_read(&rwl);

	/* Wake up read, incase it was blocked */
	wakeup(&head);
	return;
}

void
acct_rename(struct process *pr, struct vnode *vn_cmp, const char *new_path, int err) 
{
	struct message *acct_msg;
	struct tree_node *find_node, *res;
	uint32_t f_events, f_conds;			/* File Unique events */

	
	rw_enter_read(&rwl);

	/* Avert bamboozle */
	if(vn_cmp == NULL) {
		rw_exit_read(&rwl);
		return;						
	}

	/* This file currently tracked ? */
	find_node = malloc(sizeof(struct tree_node),  M_DEVBUF, M_WAITOK | M_ZERO);
	find_node->v = vn_cmp;

	/* Test for matching v_id in tree */
	res = RB_FIND(vnodetree, &rb_head, find_node);

	free(find_node, M_DEVBUF, sizeof(struct tree_node));

	if (res == NULL) {
		rw_exit_read(&rwl);
		return;  			/* We aren't tracking this */
	}

	/* At this point the file is tracked, so drop it before we return */
	fcount--;

	/* Rename acct globally disabled */
	if ((acct_audit_stat & ACCT_ENA_RENAME) == 0) {	
		remove_from_tree(res);
		rw_exit_read(&rwl);
		return;		
	}

	/* Device not opened, no need to queue anything */
	if (device_opened == 0) {
		remove_from_tree(res);
		rw_exit_read(&rwl);
		return;
	}

	/* File conditions match the open call? */
	f_events = res->audit_events;
	f_conds = res->audit_conds;

	/* File doesn't have rename accounting set */
	if ((f_events & ACCT_ENA_RENAME) == 0) {
		remove_from_tree(res);
		rw_exit_read(&rwl);
		return;
	}

	if (acct_mode_ok(f_conds, err) == false) {
		remove_from_tree(res);
		rw_exit_read(&rwl);	 //TODO Check These
		return;				/* Succes/Failure condition mismatch */
	}

	/* Construct message */
	
	/* Commited to processing the message now... */
	acct_msg = malloc(sizeof(struct message), M_DEVBUF, M_WAITOK | M_ZERO);

	/* Set internal message data */
	acct_msg->type = ACCT_MSG_RENAME;
	acct_msg->size = sizeof(struct acct_rename);

	/* Update message common fields within this message */
	acct_msg->data.rename_d.ac_common = construct_common(pr, ACCT_MSG_RENAME);

	/* Update Rename message specific fields */
	memcpy(acct_msg->data.rename_d.ac_new, new_path, PATH_MAX);
	memcpy(acct_msg->data.rename_d.ac_path, res->path, PATH_MAX);
	acct_msg->data.rename_d.ac_errno = err;

	/* Add to queue */
	TAILQ_INSERT_TAIL(&head, acct_msg, entries);
	remove_from_tree(res);			/* Removing since rename event */
	rw_exit_read(&rwl);

	/* Wake up read, incase it was blocked */
	wakeup(&head);
	return;
}

void
acct_open(struct process *pr, struct vnode *vn_cmp, int o_flags, int err) 
{
	struct message *acct_msg;
	struct tree_node *find_node, *res;
	uint32_t f_events, f_conds;			/* File Unique events */

	/* Device not opened, no need to queue anything */
	rw_enter_read(&rwl);

	if (device_opened == 0) {
		rw_exit_read(&rwl);
		return;
	}

	/* If open accounting disabled, we outchea ... */
	if ((acct_audit_stat & ACCT_ENA_OPEN) == 0) {
		rw_exit_read(&rwl);
		return;		
	}

	/* Incase a vnode wasn't resolved */
	if(vn_cmp == NULL) {
		rw_exit_read(&rwl);
		return;						
	}

	/* This file currently tracked ? */
	find_node = malloc(sizeof(struct tree_node),  M_DEVBUF, M_WAITOK | M_ZERO);
	find_node->v = vn_cmp;

	/* Test for matching v_id in tree */
	res = RB_FIND(vnodetree, &rb_head, find_node);

	free(find_node, M_DEVBUF, sizeof(struct tree_node));

	if (res == NULL) {
		rw_exit_read(&rwl);
		return;  			/* We aren't tracking this */
	}

	/* File conditions match the open call? */
	f_events = res->audit_events;
	f_conds = res->audit_conds;

	/* File doesn't have open accounting set */
	if ((f_events & ACCT_ENA_OPEN) == 0) {
		rw_exit_read(&rwl);
		return;
	}

	uprintf("Open Flags: %d, Err: %d\n", o_flags, err);

	if (acct_this_message(f_conds, o_flags, err) == false) {
		rw_exit_read(&rwl);	 //TODO Check These
		return;				/* Condition mismatch */
	}

	/* Construct message */
	uprintf("Conds Valid\n");

	/* Commited to processing the message now... */
	acct_msg = malloc(sizeof(struct message), M_DEVBUF, M_WAITOK | M_ZERO);

	/* Set internal message data */
	acct_msg->type = ACCT_MSG_OPEN;
	acct_msg->size = sizeof(struct acct_open);

	/* Update message common fields within this message */
	acct_msg->data.open_d.ac_common = construct_common(pr, ACCT_MSG_OPEN);

	/* Update Open message specific fields */
	memcpy(acct_msg->data.open_d.ac_path, res->path, PATH_MAX);
	acct_msg->data.open_d.ac_mode = o_flags;
	acct_msg->data.open_d.ac_errno = err;

	/* Add to queue */
	TAILQ_INSERT_TAIL(&head, acct_msg, entries);
	rw_exit_read(&rwl);

	/* Wake up read, incase it was blocked */
	wakeup(&head);
	return;
}


bool
acct_this_message(uint32_t f_conds, uint32_t o_flags, int err)
{

	if (acct_mode_ok(f_conds, err) && acct_conds_ok(f_conds, o_flags))	
		return true;

	return false;
}

bool 
acct_conds_ok(uint32_t f_conds, uint32_t o_flags) 
{
	if (((f_conds & ACCT_COND_READ) == 0) && ((f_conds & ACCT_COND_WRITE) == 0)) 
		return false;			/* R/W not set */
	

	if ((f_conds & ACCT_COND_READ) && (f_conds & ACCT_COND_WRITE)) 
		return true;			/* R/W both set*/
	

	if ((f_conds & ACCT_COND_READ) && (((o_flags == O_RDONLY)) || (o_flags & O_RDWR))) 
		return true;			/* Read set, oflags match, O_RDONLY = 0x00 */
	

	if ((f_conds & ACCT_COND_WRITE) && ((o_flags & O_WRONLY) || (o_flags & O_RDWR))) 
		return true;			/* Write set, oflages match */
	

	return false; 
}

bool
acct_mode_ok(uint32_t f_conds, int err) 
{
	if ((f_conds & ACCT_COND_SUCCESS) && (f_conds & ACCT_COND_FAILURE)) 
		return true;			/* Account both failed/succeeded messages */
	

	if (((f_conds & ACCT_COND_SUCCESS) == 0) && ((f_conds & ACCT_COND_FAILURE) == 0)) 
		return false;			/* No succes/fail set, dont account */
	

	if ((f_conds & ACCT_COND_SUCCESS) && (err == 0)) 
		return true;		/* Success  set, no error */
	
	

	if ((f_conds & ACCT_COND_FAILURE) && (err != 0)) 
		return true;		/* Failure set and error, OK */
	
	return false;

}

int
acctclose(dev_t dev, int flag, int mode, struct proc *p)
{
	//TODO Clear the mfkn list my doggie...

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