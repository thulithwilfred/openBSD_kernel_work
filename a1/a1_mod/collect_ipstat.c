#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <err.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>

/* Ip Stat Includes */
#include <sys/queue.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include <net/route.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>
#include <netinet/igmp_var.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_seq.h>

#include <arpa/inet.h>

#include "metrics.h"
#include "log.h"

struct metric_ops ipstat_metric_ops = {
	.mo_collect = NULL,
	.mo_free = NULL
};

struct ipstat_modpriv {
	struct ipstat stats;
	struct metric *ip_stats;
};

/**
 * @brief Regist a new ip_stat module to metrics
 * 
 * @param r registry 
 * @param modpriv module private data 
 */
static void
ipstat_register(struct registry *r, void **modpriv) {
    struct ipstat_modpriv *priv;

	priv = calloc(1, sizeof(struct ipstat_modpriv));
	*modpriv = priv;

	priv->ip_stats = metric_new(r, "ip_protocal_stats", 
		"Various aspects of ip protocal statistics",
		METRIC_COUNTER, METRIC_VAL_UINT64, NULL, &ipstat_metric_ops,
		metric_label_new("ip_stats", METRIC_VAL_STRING),
	    NULL);
}

/**
 * @brief Callback to collect specified ip data. 
 * 
 * @param modpriv module internal data
 * @return int 0 on completion (not success)
 */
static int
ipstat_collect(void *modpriv) {

	struct ipstat_modpriv *priv = modpriv;
	size_t len = sizeof(priv->stats);
	int mib[] = { CTL_NET, PF_INET, IPPROTO_IP, IPCTL_STATS };
	

	if (sysctl(mib, sizeof(mib) / sizeof(mib[0]),
	    &priv->stats, &len, NULL, 0) == -1) {
		if (errno != ENOPROTOOPT)
			warnx("%s", "ip");
		return (0);
	}

	metric_update(priv->ip_stats, "total", priv->stats.ips_total);
	metric_update(priv->ip_stats, "badsum", priv->stats.ips_badsum);
	metric_update(priv->ip_stats, "toosmall", priv->stats.ips_toosmall);
	metric_update(priv->ip_stats, "tooshort", priv->stats.ips_tooshort);
	metric_update(priv->ip_stats, "badhlen", priv->stats.ips_badhlen);
	metric_update(priv->ip_stats, "badlen", priv->stats.ips_badlen);
	metric_update(priv->ip_stats, "badoptions", priv->stats.ips_badoptions);
	metric_update(priv->ip_stats, "badvers", priv->stats.ips_badvers);
	metric_update(priv->ip_stats, "fragments", priv->stats.ips_fragments);
	metric_update(priv->ip_stats, "fragdropped", priv->stats.ips_fragdropped);
	metric_update(priv->ip_stats, "badfrags", priv->stats.ips_badfrags);
	metric_update(priv->ip_stats, "fragtimeout", priv->stats.ips_fragtimeout);
	metric_update(priv->ip_stats, "reassembled", priv->stats.ips_reassembled);
	metric_update(priv->ip_stats, "delivered", priv->stats.ips_delivered);
	metric_update(priv->ip_stats, "noproto", priv->stats.ips_noproto);
	metric_update(priv->ip_stats, "forward", priv->stats.ips_forward);
	metric_update(priv->ip_stats, "cantforward", priv->stats.ips_cantforward);
	metric_update(priv->ip_stats, "redirectsent", priv->stats.ips_redirectsent);
	metric_update(priv->ip_stats, "localout", priv->stats.ips_localout);
	metric_update(priv->ip_stats, "rawout", priv->stats.ips_rawout);
	metric_update(priv->ip_stats, "odropped", priv->stats.ips_odropped);
	metric_update(priv->ip_stats, "noroute", priv->stats.ips_noroute);
	metric_update(priv->ip_stats, "fragmented", priv->stats.ips_fragmented);
	metric_update(priv->ip_stats, "ofragments", priv->stats.ips_ofragments);
	metric_update(priv->ip_stats, "cantfrag", priv->stats.ips_cantfrag);
	metric_update(priv->ip_stats, "rcvmemdrop", priv->stats.ips_rcvmemdrop);
	metric_update(priv->ip_stats, "toolong", priv->stats.ips_toolong);
	metric_update(priv->ip_stats, "nogif", priv->stats.ips_nogif);
	metric_update(priv->ip_stats, "badaddr", priv->stats.ips_badaddr);
	metric_update(priv->ip_stats, "inswcsum", priv->stats.ips_inswcsum);
	metric_update(priv->ip_stats, "outswcsum", priv->stats.ips_outswcsum);
	metric_update(priv->ip_stats, "notmember", priv->stats.ips_notmember);
	metric_update(priv->ip_stats, "wrongif", priv->stats.ips_wrongif);

    return 0;
}

/**
 * @brief Module free data, will free associated data with the module. 
 * 
 * @param modpriv module internal data.
 */
static void
ipstat_free(void *modpriv) {
	struct cpu_modpriv *priv = modpriv;
	free(priv);
}


struct metrics_module_ops collect_ipstat_ops = {
	.mm_register = ipstat_register,
	.mm_collect = ipstat_collect,
	.mm_free = ipstat_free
};