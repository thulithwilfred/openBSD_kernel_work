/* $OpenBSD: env.c,v 1.10 2019/07/07 19:21:28 tedu Exp $ */
/*
 * Copyright (c) 2016 Ted Unangst <tedu@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <sys/types.h>
#include <sys/tree.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>

#include "pfexecd.h"

const char *formerpath;

struct envnode {
	RB_ENTRY(envnode) node;
	const char *key;
	const char *value;
};



struct env {
	RB_HEAD(envtree, envnode) root;
	u_int count;
};

struct env req_envnode;

static void fillenv(struct env *, const char **);
void remove_dups_from_basic(char *, struct env *);

static int
envcmp(struct envnode *a, struct envnode *b)
{
	return strcmp(a->key, b->key);
}

RB_GENERATE_STATIC(envtree, envnode, node, envcmp);

static struct envnode *
createnode(const char *key, const char *value)
{
	struct envnode *node;

	node = malloc(sizeof(*node));
	if (!node)
		err(1, NULL);
	node->key = strdup(key);
	node->value = strdup(value);
	if (!node->key || !node->value)
		err(1, NULL);
	return node;
}

static void
freenode(struct envnode *node)
{
	free((char *)node->key);
	free((char *)node->value);
	free(node);
}

static void
addnode(struct env *env, const char *key, const char *value)
{
	struct envnode *node;

	node = createnode(key, value);
	RB_INSERT(envtree, &env->root, node);
	env->count++;
}

static struct env *
createenv(const struct rule *rule, const struct passwd *mypw,
    const struct passwd *targpw)
{
	static const char *copyset[] = {
		"DISPLAY", "TERM",
		NULL
	};
	extern char **req_environ;
	struct env *env;
	u_int i;

	struct envnode *node;
	const char *e, *eq;
	size_t len;
	char name[1024];

	env = malloc(sizeof(*env));
	if (!env)
		err(1, NULL);
	RB_INIT(&env->root);
	env->count = 0;

	RB_INIT(&req_envnode.root);
	req_envnode.count = 0;

	addnode(env, "PFEXEC_USER", mypw->pw_name);
	addnode(env, "HOME", targpw->pw_dir);
	addnode(env, "LOGNAME", targpw->pw_name);
	addnode(env, "PATH", getenv("PATH"));
	addnode(env, "SHELL", targpw->pw_shell);
	addnode(env, "USER", targpw->pw_name);

	fillenv(env, copyset);

	/*
	 * Build new tree with only request environs for (Searching only)
	 * Yes, this is kinda dumb... desperate time i guess..
	 */
	for (i = 0; req_environ[i] != NULL; i++) {
		e = req_environ[i];
		/* ignore invalid or overlong names */
		if ((eq = strchr(e, '=')) == NULL || eq == e)
			continue;
		len = eq - e;
		if (len > sizeof(name) - 1)
			continue;
		memcpy(name, e, len);
		name[len] = '\0';

		/* Removes Duplicated from default env tree */
		if (rule->options & KEEPENV) {
			remove_dups_from_basic(name, env);
		}
		node = createnode(name, eq + 1);
		if (RB_INSERT(envtree, &req_envnode.root, node)) {
			/* ignore any later duplicates */
			freenode(node);
		} else {
			req_envnode.count++;
		}
	}
	return env;
}
/*
 * Remove duplicates from the default set created.
 * only to be used when keepenv is set.
 */
void
remove_dups_from_basic(char *name, struct env *env)
{
	struct envnode *node, key;

	key.key = name;
	if ((node = RB_FIND(envtree, &env->root, &key))) {
		RB_REMOVE(envtree, &env->root, node);
		freenode(node);
	}
}

static char **
flattenenv(struct env *env, const struct rule *rule)
{
	char **envp;
	struct envnode *node, *next;
	u_int i;

	if (rule->options & KEEPENV)
		envp = reallocarray(NULL, env->count + req_envnode.count + 1,
		    sizeof(char *));
	else
		envp = reallocarray(NULL, env->count + 1, sizeof(char *));

	if (!envp)
		err(1, NULL);
	i = 0;

	/* Append default env */
	RB_FOREACH_SAFE(node, envtree, &env->root, next) {
		if (asprintf(&envp[i], "%s=%s", node->key, node->value) == -1)
			err(1, NULL);
		RB_REMOVE(envtree, &env->root, node);
		freenode(node);
		i++;
	}

	node = NULL;
	next = NULL;
	/* Append KEEP env */
	if (rule->options & KEEPENV) {
		RB_FOREACH_SAFE(node, envtree, &req_envnode.root, next) {

			if (asprintf(&envp[i], "%s=%s",
			    node->key, node->value) == -1)
				err(1, NULL);

			RB_REMOVE(envtree, &req_envnode.root, node);
			freenode(node);
			i++;
		}
	}

	envp[i] = NULL;
	free(env);
	return envp;
}

static void
fillenv(struct env *env, const char **envlist)
{
	struct envnode *node, key;
	const char *e, *eq;
	const char *val;
	char name[1024];
	u_int i;
	size_t len;

	for (i = 0; envlist[i]; i++) {
		e = envlist[i];

		/* parse out env name */
		if ((eq = strchr(e, '=')) == NULL)
			len = strlen(e);
		else
			len = eq - e;
		if (len > sizeof(name) - 1)
			continue;
		memcpy(name, e, len);
		name[len] = '\0';

		/* delete previous copies */
		key.key = name;
		if (*name == '-')
			key.key = name + 1;

		/* Remove from default tree */
		if ((node = RB_FIND(envtree, &env->root, &key))) {
			RB_REMOVE(envtree, &env->root, node);
			freenode(node);
			env->count--;
		} else if ((node = RB_FIND(envtree, &req_envnode.root, &key))) {
			/* Remove from keep tree (if in here...) */
			RB_REMOVE(envtree, &req_envnode.root, node);
			freenode(node);
			req_envnode.count--;
		}

		if (*name == '-')
			continue;

		/* assign value or inherit from environ */
		if (eq) {
			val = eq + 1;
			if (*val == '$') {
				key.key = val + 1;
				if ((node = RB_FIND(envtree, &req_envnode.root,
				    &key))) {
					val = node->value;
				}
			}
		} else {
			key.key = name;
			if ((node = RB_FIND(envtree, &req_envnode.root,
			    &key))) {
				val = node->value;
			} else {
				val = NULL;
			}
		}
		/* at last, we have something to insert */
		if (val) {
			node = createnode(name, val);
			RB_INSERT(envtree, &env->root, node);
			env->count++;
		}
	}
}

char **
prepenv(const struct rule *rule, const struct passwd *mypw,
    const struct passwd *targpw)
{
	struct env *env;

	env = createenv(rule, mypw, targpw);

	if (rule->envlist) {
		fillenv(env, rule->envlist);
	}

	return flattenenv(env, rule);
}
