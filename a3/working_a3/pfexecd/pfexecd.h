struct rule {
	int action;
	int options;
	const char *ident;
	const char *target;
	const char *cmd;
	const char **cmdargs;
	const char **envlist;
	const char **grplist;
	const char *chroot_path;
};

extern struct rule **rules;
extern size_t nrules;
extern int parse_errors;

struct passwd;
extern const char *formerpath;
extern char **req_environ;

char **prepenv(const struct rule *, const struct passwd *,
    const struct passwd *);


#define PERMIT 1
#define DENY 2

#define NOPASS 		(1<<0)
#define KEEPENV 	(1<<1)
#define PERSIST 	(1<<2)
#define NOLOG 		(1<<3)
#define SETENV		(1<<4)
#define KEEPGROUPS 	(1<<5)
#define SETGROUPS 	(1<<6)
#define CHROOT		(1<<7)

