/*
 *
 * Copyright 2020 The University of Queensland
 * Author: Alex Wilson <alex@uq.edu.au>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/types.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/sysctl.h>
#include <sys/ioctl.h>
#include <net/pfvar.h>

#include "metrics.h"
#include "log.h"

struct pf_modpriv {
	struct pf_status status;
	struct metric *pf_running;

	struct metric *pf_states;
	struct metric *pf_state_ops;

	struct metric *pf_src_nodes;
	struct metric *pf_src_node_ops;

	struct metric *pf_state_limit;
	struct metric *pf_src_limits;

	struct metric *pf_overloads;
	struct metric *pf_overload_flushes;

	struct metric *pf_drops;
};

struct metric_ops pf_metric_ops = {
	.mo_collect = NULL,
	.mo_free = NULL
};

static void
pf_register(struct registry *r, void **modpriv)
{
	struct pf_modpriv *priv;

	priv = calloc(1, sizeof(struct pf_modpriv));
	*modpriv = priv;

	priv->pf_running = metric_new(r, "pf_running",
	    "Indicates whether pf is running",
	    METRIC_GAUGE, METRIC_VAL_UINT64, NULL, &pf_metric_ops, NULL);

	priv->pf_states = metric_new(r, "pf_states",
	    "Number of states currently tracked by pf",
	    METRIC_GAUGE, METRIC_VAL_UINT64, NULL, &pf_metric_ops, NULL);
	priv->pf_state_ops = metric_new(r, "pf_state_ops_total",
	    "Number of pf state-related operations executed",
	    METRIC_COUNTER, METRIC_VAL_UINT64, NULL, &pf_metric_ops,
	    metric_label_new("op", METRIC_VAL_STRING), NULL);

	priv->pf_src_nodes = metric_new(r, "pf_src_nodes",
	    "Number of source count nodes currently tracked by pf",
	    METRIC_GAUGE, METRIC_VAL_UINT64, NULL, &pf_metric_ops, NULL);
	priv->pf_src_node_ops = metric_new(r, "pf_src_node_ops_total",
	    "Number of pf srcnode-related operations executed",
	    METRIC_COUNTER, METRIC_VAL_UINT64, NULL, &pf_metric_ops,
	    metric_label_new("op", METRIC_VAL_STRING), NULL);

	priv->pf_state_limit = metric_new(r, "pf_state_limit_hits_total",
	    "Number of times the global pf state limit has been hit",
	    METRIC_COUNTER, METRIC_VAL_UINT64, NULL, &pf_metric_ops, NULL);
	priv->pf_src_limits = metric_new(r, "pf_src_limit_hits_total",
	    "Number of times various kinds of pf src limits have been hit",
	    METRIC_COUNTER, METRIC_VAL_UINT64, NULL, &pf_metric_ops,
	    metric_label_new("limit", METRIC_VAL_STRING), NULL);

	priv->pf_overloads = metric_new(r, "pf_overload_adds_total",
	    "Number of times entries have been added to overload tables",
	    METRIC_COUNTER, METRIC_VAL_UINT64, NULL, &pf_metric_ops, NULL);
	priv->pf_overload_flushes = metric_new(r, "pf_overload_flushes_total",
	    "Number of times entries have been flushed from overload tables",
	    METRIC_COUNTER, METRIC_VAL_UINT64, NULL, &pf_metric_ops, NULL);

	priv->pf_drops = metric_new(r, "pf_drops_total",
	    "Number of times packets have been dropped due to different "
	    "pf-related reasons",
	    METRIC_COUNTER, METRIC_VAL_UINT64, NULL, &pf_metric_ops,
	    metric_label_new("reason", METRIC_VAL_STRING), NULL);
}

static int
pf_collect(void *modpriv)
{
	struct pf_modpriv *priv = modpriv;
	size_t size = sizeof(priv->status);
	int mib[3] = { CTL_KERN, KERN_PFSTATUS };
	const char *drop_names[] = PFRES_NAMES;
	size_t i;

	if (sysctl(mib, 2, &priv->status, &size, NULL, 0) == -1) {
		tslog("failed to get pf status: %s", strerror(errno));
		return (0);
	}

	metric_update(priv->pf_running, priv->status.running);

	metric_update(priv->pf_states, priv->status.states);
	metric_update(priv->pf_state_ops, "search",
	    priv->status.fcounters[FCNT_STATE_SEARCH]);
	metric_update(priv->pf_state_ops, "insert",
	    priv->status.fcounters[FCNT_STATE_INSERT]);
	metric_update(priv->pf_state_ops, "remove",
	    priv->status.fcounters[FCNT_STATE_REMOVALS]);

	metric_update(priv->pf_src_nodes, priv->status.src_nodes);
	metric_update(priv->pf_src_node_ops, "search",
	    priv->status.scounters[SCNT_SRC_NODE_SEARCH]);
	metric_update(priv->pf_src_node_ops, "insert",
	    priv->status.scounters[SCNT_SRC_NODE_INSERT]);
	metric_update(priv->pf_src_node_ops, "remove",
	    priv->status.scounters[SCNT_SRC_NODE_REMOVALS]);

	metric_update(priv->pf_state_limit,
	    priv->status.lcounters[LCNT_STATES]);

	metric_update(priv->pf_src_limits, "max-src-states",
	    priv->status.lcounters[LCNT_SRCSTATES]);
	metric_update(priv->pf_src_limits, "max-src-nodes",
	    priv->status.lcounters[LCNT_SRCNODES]);
	metric_update(priv->pf_src_limits, "max-src-conn",
	    priv->status.lcounters[LCNT_SRCCONN]);
	metric_update(priv->pf_src_limits, "max-src-conn-rate",
	    priv->status.lcounters[LCNT_SRCCONNRATE]);

	metric_update(priv->pf_overloads,
	    priv->status.lcounters[LCNT_OVERLOAD_TABLE]);
	metric_update(priv->pf_overload_flushes,
	    priv->status.lcounters[LCNT_OVERLOAD_FLUSH]);

	for (i = 0; drop_names[i] != NULL; ++i) {
		metric_update(priv->pf_drops, drop_names[i],
		    priv->status.counters[i]);
	}

	return (0);
}

static void
pf_free(void *modpriv)
{
	struct pf_modpriv *priv = modpriv;
	free(priv);
}

struct metrics_module_ops collect_pf_ops = {
	.mm_register = pf_register,
	.mm_collect = pf_collect,
	.mm_free = pf_free
};
