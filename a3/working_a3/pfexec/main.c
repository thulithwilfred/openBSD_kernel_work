/**
 * COMP3301 - Assingment 3
 *
 * pfexec is a commandline utility that processes it's arguments and calls the pfexecve() system call.
 * 
 * Author	: Wilfred MK
 * SID		: S4428042
 * Riv		: 0.1
 * Last Updated	: 8/10/2021
 */

#include <sys/param.h>
#include <sys/pfexec.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

/* Define buffer limits */
#define EXE_MAXLEN 256
#define ARGS_MAXLEN 256

/* Define options flags */
#define	PFEXEC_S		(1 << 0)
#define	PFEXEC_U		(1 << 1)
#define	PFEXEC_N		(1 << 2)

struct pfexec_data {
	char executable_name[EXE_MAXLEN];
	char args_list[ARGS_MAXLEN];
	char username[LOGIN_NAME_MAX];
};

/* Define errors and errvals used in pfexec */
enum pfexec_errno
{
		E_BADARGS = 1,
		E_BADUNAME = 2
};

/**
 * @brief Prints the program usage message and exits.
 * 
 */
__dead static void
usage(void) 
{
		fprintf(stderr, "Usage: pfexec [options] <executable> [args...] \npfexec [options] -s\n\n");
		fprintf(stderr, "Options:\n");
		fprintf(stderr, "\t-u user\tAssume the privileges of the given user instead of \"root\"\n");
		fprintf(stderr, "\t-n\tNon-iteractive/batch mode: no prompts are used\n\t\tif prompts are required, will fail\n");
		fprintf(stderr, "\t-s\tExecute a shell, rather than a specific command\n");

		exit(E_BADARGS);
}

/**
 * @brief Set PF flags based on arguments to this programs
 * @note  PF flags are defined in include/sys/pfexec.h
 * 
 * @param opt_flag argument flags to this program
 * @return set PF flags
 */
uint32_t gen_pfo_flags(uint32_t opt_flag)
{
	uint32_t pfo_flag = 0;

	if (opt_flag & PFEXEC_N)
		pfo_flag |= PFEXECVE_NOPROMPT;

	if (opt_flag & PFEXEC_U) 
		pfo_flag |= PFEXECVE_USER;

	return pfo_flag;
}

/**
 * @brief Execute a shell based on SHELL env variable, else run /bin/ksh.
 *		 	
 * 
 * @param opt_flag set privileges and interactive mode of the shell
 * @return 0 on success or errno
 */
int 
execute_shell(uint32_t opt_flag, struct pfexec_data *d) 
{
		struct pfexecve_opts p_opts;
		char *shell_path = malloc(sizeof(char) * 128);

		/* Evaluate SHELL env variable */
		if (getenv("SHELL") == NULL ) 
			strcpy(shell_path, "/bin/ksh");
		else
			shell_path = getenv("SHELL");

		p_opts.pfo_flags = gen_pfo_flags(opt_flag);	

		/* Username defined, copy in uname */
		if (opt_flag & PFEXEC_U) 
			strcpy(p_opts.pfo_user, d->username);
			
		/* Call to pfexecve ? */
		printf("UNAME: %s\nSHELL: %s\n", p_opts.pfo_user, shell_path);
		return 0;
}

/**
 * @brief Process pfexec based on the provided options
 * 
 * @param opt_flag options
 * @param d holds executable and exec args
 * @return 0 on success, else errno
 */
int
process_pfexec(uint32_t opt_flag, struct pfexec_data *d)
{
		struct pfexecve_opts p_opts;

		/* Exexute Shell */
		if (opt_flag & PFEXEC_S)
			return execute_shell(opt_flag, d);

		p_opts.pfo_flags = gen_pfo_flags(opt_flag);	

		/* Username defined, copy in uname */
		if (opt_flag & PFEXEC_U) 		
			strcpy(p_opts.pfo_user, d->username);	

		/* Call to pfexecve ? */
		printf("UNAME: %s\nEXEC: %s, ARGS: %s\n", p_opts.pfo_user, d->executable_name, d->args_list);

		return (0);
}

/**
 * @brief pfexec is a commandline utility that processes it's arguments and calls the pfexecve() system call.
 * 
 * @return int 0 on success or errno
 */
int
main(int argc, char** argv) 
{
		struct pfexec_data *d;
		int ch, err = 0;
		uint32_t opt_flag = 0;

		if (argc <= 1)
			usage();
		
		d = malloc(sizeof(struct pfexec_data));

		while((ch = getopt(argc, argv, "u:ns")) != -1) {
			switch(ch) {
			case 'u':
				strcpy(d->username, optarg);
				opt_flag |= PFEXEC_U;
				if (strlen(d->username) < 1)
					return E_BADUNAME;
				break;
			case 'n':
				opt_flag |= PFEXEC_N;
				break;
			case 's':
				opt_flag |= PFEXEC_S;
				break;
			default:
				usage();
			}
		}

		argc -= optind;
		argv += optind;

		/* Execute a shell, with specified options */
		if (opt_flag & PFEXEC_S) {
			/* Should not have any remaining args */
			if (argc != 0)
				usage(); 
			return process_pfexec(opt_flag, d);
		}

		if (argc == 0)
			usage(); 

		/* Copy in executable name */
		strcpy(d->executable_name, *argv);

		/* Create an args list */
		for(int i = 1; i < argc ; ++i) {
			strcat(d->args_list, argv[i]);
			strcat(d->args_list, " ");
		}

		err = process_pfexec(opt_flag, d);

		free(d);
		return (err);
}

