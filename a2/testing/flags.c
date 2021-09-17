#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/syslimits.h>
#include <sys/ioccom.h>


#define	ACCT_ENA_FORK		(1 << 0)
#define	ACCT_ENA_EXEC		(1 << 1)
#define	ACCT_ENA_EXIT		(1 << 2)
#define	ACCT_ENA_OPEN		(1 << 3)
#define	ACCT_ENA_CLOSE		(1 << 4)
#define	ACCT_ENA_RENAME		(1 << 5)
#define	ACCT_ENA_UNLINK		(1 << 6)
#define	ACCT_ENA_ALL		ACCT_ENA_FORK | \
				ACCT_ENA_EXEC | \
				ACCT_ENA_EXIT | \
				ACCT_ENA_OPEN | \
				ACCT_ENA_CLOSE | \
				ACCT_ENA_RENAME | \
				ACCT_ENA_UNLINK

#define ACC_TEMP		ACCT_ENA_FORK | \
				ACCT_ENA_EXEC | \
				ACCT_ENA_OPEN | \
				ACCT_ENA_CLOSE | \
				ACCT_ENA_RENAME | \
				ACCT_ENA_UNLINK  

uint32_t flag = 0;

void set_audit_stat(uint32_t set_mask) 
{
	flag |= set_mask;

}

void clear_audit_stat(uint32_t clear_mask)
{
	flag &= ~(clear_mask);
}

int main(void) {

	set_audit_stat(ACCT_ENA_OPEN | ACCT_ENA_EXEC);

	if (flag & ACCT_ENA_OPEN) 
		printf("OPEN OK\n");

	if (flag & ACCT_ENA_FORK)
		printf("Bad\n");


	if (flag & ACCT_ENA_EXEC)
		printf("EXEC OK\n");

	if (flag & ACCT_ENA_EXIT)
		printf("Bad\n");

	if (flag & ACCT_ENA_RENAME)
		printf("Bad\n");

	if (flag & ACCT_ENA_CLOSE)
		printf("Bad\n");

	return (0);
}


