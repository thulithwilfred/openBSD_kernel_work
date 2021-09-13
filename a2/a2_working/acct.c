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

#include "acct.h"

int
acctopen(dev_t dev, int flag, int mode, struct proc *p)
{
	return 0;
}

int
acctclose(dev_t dev, int flag, int mode, struct proc *p)
{
	return 0;
}

int 
acctread(dev_t dev, struct uio *uio, int flags)
{
	return 0;
}

int
acctwrite(dev_t dev, struct uio *uio, int flags)
{
	return 0;	
}


int 
acctioctl(dev_t dev, u_long cmd, caddr_t data, int flag, struct proc *p)
{
	return 0;
}

int 
acctpoll(dev_t dev, int events, struct proc *p)
{
	return 0;
}

int
acctkqfilter(dev_t dev, struct knote *kn)
{
	return 0;
}

int acctattach(int num) 
{
	return 0;
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