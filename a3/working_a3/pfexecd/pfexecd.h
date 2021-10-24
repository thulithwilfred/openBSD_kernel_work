struct rule {
	int action;
	int options;
	const char *ident;
	const char *target;
	const char *cmd;
	const char **cmdargs;
	const char **envlist;
};

extern struct rule **rules;
extern size_t nrules;
extern int parse_errors;

extern const char *formerpath;

#define PERMIT 1
#define DENY 2

#define NOPASS 0x1
#define KEEPENV 0x2
#define PERSIST 0x4
#define NOLOG 0x8