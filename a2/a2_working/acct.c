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

#include <sys/filio.h>
#include <sys/fcntl.h>

#include <sys/rwlock.h>

#include "acct.h"

/** 
 * TODO: 1. Parse the process hooks in here and set the appropriate structs and add them to the queue.
 *		 2. Figure out where to put the kernel hooks for file auditing. 
 */

/* Local Defines */
#define READ_ONLY 1 	/* Read Only Mode */

struct rwlock rwl = RWLOCK_INITIALIZER("acct_lock");

int ronly_flag = 0;

/**
 * @brief Initialise state required for operations 
 * 
 */
int acctattach(int num) 
{
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
		
	return (0);
}



int 
acctread(dev_t dev, struct uio *uio, int flags)
{
	return 0;
}


int 
acctioctl(dev_t dev, u_long cmd, caddr_t data, int flag, struct proc *p)
{
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
			break;
		case ACCT_IOC_DISABLE:
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


void
acct_fork(struct process *data) 
{

}

void
acct_exec(struct process *data)
{

}

void
acct_exit(struct process *data)
{
	
}