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
#include <sys/conf.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/filio.h>
#include <sys/fcntl.h>
#include <sys/proc.h>

#include <sys/rwlock.h>
#include <sys/tty.h>

#include "acct.h"

/** 
 * TODO: 1. Parse the process hooks in here and set the appropriate structs and add them to the queue.
 *		 2. Figure out where to put the kernel hooks for file auditing. 
 */

/* RW Lock */
struct rwlock rwl = RWLOCK_INITIALIZER("acct_lock");

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


struct message {
	TAILQ_ENTRY(message) entries;
	int type; 						/* Defines type of data the message is, i.e struct acct_fork relates to ACCT_MSG_FORK*/
	unsigned int size; 				/* Total size of the data held by 'data' in bytes, set by sender */
	union message_data data;		/* acct message */
};

TAILQ_HEAD(message_queue, message) head; 

/* Local Defines */
#define ALL_OFF 0x00
#define READ_ONLY 1 	/* Read Only Mode */


/* Globals */
int ronly_flag = 0;
int sequence_num = 0;
uint32_t acct_audit_stat = ALL_OFF;

/**
 * @brief Initialise state required for operations 
 * 
 */
int acctattach(int num) 
{
	/* Initialise the message queue for acct messages */
	TAILQ_INIT(&head);
	/* Clear Audit Stats */
	acct_audit_stat = ALL_OFF;
	return 0;
}

int
acctopen(dev_t dev, int flag, int mode, struct proc *p)
{
	/* Allow only 0th minor to be opened */
	if (minor(dev) != 0)
		return (ENXIO);

	/* If not opened exclusively */
	if (!(flag & FFLAGS(O_EXCL)))
		return EEXIST;

	/* If not opened for reading or read/write */
	if (!(flag & FFLAGS(O_RDONLY) || !(flag & FFLAGS(O_RDWR))))
		return (EPERM);

	if (flag & FFLAGS(O_RDONLY))
		ronly_flag = READ_ONLY;
	
	/* Reset Sequence Num */
	rw_enter_write(&rwl); /* The lock is probably not needed here? */
	sequence_num = 0;
	rw_exit_write(&rwl);

	return (0);
}



int 
acctread(dev_t dev, struct uio *uio, int flags)
{
	return 0;
}

/**
 * @brief Set the audit stats 
 * 
 * @param set_mask bit fields to be set 
 */
void set_audit_stats(uint32_t set_mask) 
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
	struct acct_ctl *ctl = (struct acct_ctl*)data;

	/* Support for generic ioctl requests */
	switch(cmd) {
		case FIONREAD:
			/* Get the number of bytes that are immediately available for reading*/
			//TODO: Get len of next struct in queue
			*(int *)data = 0;
			break;
		case FIONBIO:
			/*  Handled in the upper FS layer */
			break;
		case FIOASYNC:
			return (EOPNOTSUPP);
	}

	/* Device specific ioctls not accepted in read only mode */
	if (ronly_flag == READ_ONLY) 
		return (ENOTTY);

	/* Support for device specific ioctl requests */
	switch(cmd) {
		case ACCT_IOC_STATUS:
			break;
		case ACCT_IOC_FSTATUS:
			break;
		case ACCT_IOC_ENABLE:		
			set_audit_stats(ctl->acct_ena);		/* set features to enable */

			rw_enter_read(&rwl);
			ctl->acct_ena = acct_audit_stat;	/* update with currently enabled features */
			rw_exit_read(&rwl);
			break;
		case ACCT_IOC_DISABLE:
			clear_audit_stats(ctl->acct_ena);		/* set features to disable */

			rw_enter_read(&rwl);
			ctl->acct_ena = acct_audit_stat;		/* update with currently enabled features  */
			rw_exit_read(&rwl);
			break;
		case ACCT_IOC_TRACK_FILE:
			break;
		case ACCT_IOC_UNTRACK_FILE:
			break;
		default:
			/* Inappropriate ioctl for device */
			return (ENOTTY);
	}
	return (0);
}

void
acct_fork(struct process *pdata) 
{
	struct acct_common common;
	struct timespec uptime;
	struct message *acct_msg;

	/* if fork accounting not enabled, let's not worry about this... */
	rw_enter_read(&rwl);
	if((acct_audit_stat & ACCT_ENA_FORK) == 0) {
		rw_exit_read(&rwl);
		return;
	}
	rw_exit_read(&rwl);

	/* Commited to processing the message now... */

	/* Sequence begins from index 0 */
	rw_enter_write(&rwl);
	common.ac_seq = sequence_num;
	sequence_num++;
	rw_exit_write(&rwl);

	acct_msg = malloc(sizeof(struct message), M_DEVBUF, M_WAITOK | M_ZERO);
	
	/* Set internal message data */
	acct_msg->type = ACCT_MSG_FORK;
	acct_msg->size = sizeof(struct acct_fork);

	/* 
	 * Create message common fields and update 'this' message. 
	 * Enqueue the message, once required data fields are filled out 
	 */
	
	/* Set msg type */
	common.ac_type = ACCT_MSG_FORK;
	
	/* Set len (size bytes) */
	common.ac_len = sizeof(struct acct_fork);

	/*  Get command name */
	memcpy(common.ac_comm, pdata->ps_comm, sizeof(common.ac_comm));

	/* Get Time */
	nanouptime(&uptime);
	timespecsub(&uptime, &pdata->ps_start, &common.ac_etime); 	/* Calculate and update elapsed time*/
	common.ac_btime = pdata->ps_start; 							/* Get Starting time */

	/* Get Ids */
	common.ac_pid = pdata->ps_ppid;								/* Referenced in process_new(), kern_fork.c */
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

	/* Update message common fields within this message */
	acct_msg->data.fork_d.ac_common = common;

	/* Set child pid */
	acct_msg->data.fork_d.ac_cpid = pdata->ps_pid; 				 /* Referenced in process_new(), kern_fork.c */

	/* Enqueue Data */
	rw_enter_write(&rwl);
	TAILQ_INSERT_TAIL(&head, acct_msg, entries);
	rw_exit_write(&rwl);
} 

void
acct_exec(struct process *data)
{

}

void
acct_exit(struct process *data)
{
	
}


int
acctclose(dev_t dev, int flag, int mode, struct proc *p)
{
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


