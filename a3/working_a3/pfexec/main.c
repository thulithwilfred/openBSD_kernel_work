/*
 * COMP3301 - Assingment 3
 *
 * pfexec is a commandline utility that processes it's arguments and calls the
 * pfexecve() system call.
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
 * @(#)main.c v0.1 (UQ) - Wilfred MK
 */


#include <sys/param.h>
#include <sys/pfexec.h>
#include <sys/limits.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <err.h>

/* Define buffer limits */
#define EXE_MAXLEN 256
#define ARGS_MAXLEN 256

/* Define options flags */
#define	PFEXEC_S		(1 << 0)
#define	PFEXEC_U		(1 << 1)
#define	PFEXEC_N		(1 << 2)

struct pfexec_data {
	char executable_name[PATH_MAX];
	char username[LOGIN_NAME_MAX];
	char **args;
	uint32_t args_count;  /* To be used when freeing. */
};

/* Define errors and errvals used in pfexec */
enum pfexec_errno
{
	E_BADARGS = 1,
	E_BADUNAME = 2,
	E_BADEXE = 3,
	E_TOOLONG = 4,
	E_FAILED_PFEXEC = 5
};

/*
 * @brief Prints the program usage message and exits.
 */
__dead static void
usage(void)
{
	fprintf(stderr, "Usage: pfexec [options] <executable> [args...]\n"
	"pfexec[options] -s\n\n");
	fprintf(stderr, "Options:\n");

	fprintf(stderr, "\t-u user\tAssume the privileges of the given"
	    " user instead of \"root\"\n");
	fprintf(stderr, "\t-n\tNon-iteractive/batch mode:"
	" no prompts are used\n\t\t if prompts are required, will fail\n");
	fprintf(stderr, "\t-s\tExecute a shell, rather than a specific command,"
	    " no options\n");
	exit(E_BADARGS);
}

/*
 * Free allocated memory for pfexec arguments
 */
void
free_args(char **args, uint32_t num_elements)
{
	for (int i = 0; i < num_elements; ++i) {
		free(args[i]);
	}
	free(args);
}

/*
 * Set PF flags based on arguments to this programs
 * @note  PF flags are defined in include/sys/pfexec.h
 */
uint32_t
gen_pfo_flags(uint32_t opt_flag)
{
	uint32_t pfo_flag = 0;

	if (opt_flag & PFEXEC_N)
		pfo_flag |= PFEXECVE_NOPROMPT;

	if (opt_flag & PFEXEC_U)
		pfo_flag |= PFEXECVE_USER;

	return pfo_flag;
}

/*
 * Execute a shell based on SHELL env variable, else run /bin/ksh.
 */
int
execute_shell(uint32_t opt_flag, struct pfexec_data *d)
{
	struct pfexecve_opts p_opts;
	int err_val = 0, i;
	char *shell_path = malloc(sizeof(char) * 128);
	char **args = malloc(sizeof(char *) * 2);
	args[0] = malloc(sizeof(char) * 512);
	args[1] = malloc(sizeof(char) * 12);

	/* Evaluate SHELL env variable */
	if (getenv("SHELL") == NULL)
		strcpy(shell_path, "/bin/ksh");
	else
		strcpy(shell_path, getenv("SHELL"));

	/* Setup args */
	strncpy(args[0], shell_path, 512);
	args[1] = NULL;

	p_opts.pfo_flags = gen_pfo_flags(opt_flag);

	/* Username defined, copy in uname */
	if (opt_flag & PFEXEC_U)
		strcpy(p_opts.pfo_user, d->username);

	/* Call to pfexecve */
	err_val = pfexecvp(&p_opts, shell_path, args);

	/* If exec succeeded, this code never runs */
	free(shell_path);
	for (i = 0; i < 2; ++i)
		free(args[i]);

	free(args);

	return err_val;
}

/*
 * Process pfexec based on the provided options
 */
int
process_pfexec(uint32_t opt_flag, struct pfexec_data *d)
{
	struct pfexecve_opts p_opts;
	int err_val = 0;

	/* Exexute Shell */
	if (opt_flag & PFEXEC_S)
		return execute_shell(opt_flag, d);

	p_opts.pfo_flags = gen_pfo_flags(opt_flag);

	/* Username defined, copy in uname */
	if (opt_flag & PFEXEC_U)
		strcpy(p_opts.pfo_user, d->username);

	/* Call to pfexecve */
	err_val = pfexecvp(&p_opts, d->executable_name, d->args);

	/* If exec succeeded, this code never runs */
	return (err_val);
}

/*
 * pfexec is a commandline utility that processes
 *		 it's arguments and calls the pfexecve() system call.
 */
int
main(int argc, char **argv)
{
	struct pfexec_data *d;
	int ch, errno = 0;
	uint32_t opt_flag = 0;

	if (argc <= 1)
		usage();

	d = malloc(sizeof(struct pfexec_data));
	bzero(d, sizeof(struct pfexec_data));

	while ((ch = getopt(argc, argv, "u:ns")) != -1) {
		switch (ch) {
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

		errno = execute_shell(opt_flag, d);

		if (errno)
			goto early_close;
	}

	if (argc == 0)
		usage();

	/* Copy in executable name */
	if (strlen(*argv) > EXE_MAXLEN)
		return E_BADEXE;

	strlcpy(d->executable_name, *argv, PATH_MAX);

	/*
	 *	Arguments Array
	 *	argc here holds prog name and remaining args, +1 to add NUL
	 *	terminate.
	 */
	d->args = malloc(sizeof(char *) * ((argc) + 1));

	/* Args first element should be progname */
	d->args[0] = malloc(sizeof(char) * strlen(*argv));
	strlcpy(d->args[0], *argv, EXE_MAXLEN);

	/* Create an args list */
	for (int i = 1; i < argc; ++i) {
		if (strlen(argv[i]) > ARG_MAX)
			return E_TOOLONG;
		d->args[i] = malloc(sizeof(char) * strlen(argv[i]));
		strcpy(d->args[i], argv[i]);
		d->args_count++;
	}

	/* Null terminate args */
	d->args[d->args_count + 1] = (char *)0;

	errno = process_pfexec(opt_flag, d);

	/* Will only get here if pfexecve failed */
	free_args(d->args, d->args_count);

early_close:
	free(d);
	if (errno)
		err(errno, "pfexecvp");

	return (0);
}