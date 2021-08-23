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
	struct metric *pckts, *frgmnt, *dgram, *total_tx_rx;
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


	priv->dgram = metric_new(r, "ip_stat_dgram_info", 
		"IP datagram rx/tx statistics, in datagrams(s)",
		METRIC_COUNTER, METRIC_VAL_UINT64, NULL, &ipstat_metric_ops,
		metric_label_new("reason", METRIC_VAL_STRING),
	    NULL); 

	priv->pckts = metric_new(r, "ip_stat_packet_info", 
		"IP packet tx/rx statistics, in packet(s)",
		METRIC_COUNTER, METRIC_VAL_UINT64, NULL, &ipstat_metric_ops,
		metric_label_new("reason", METRIC_VAL_STRING),
	    NULL); 

	priv->frgmnt = metric_new(r, "ip_stat_fragments_info", 
		"IP fragments tx/rx statistics, in fragment(s)",
		METRIC_COUNTER, METRIC_VAL_UINT64, NULL, &ipstat_metric_ops,
		metric_label_new("reason", METRIC_VAL_STRING),
	    NULL); 

	priv->total_tx_rx = metric_new(r, "ip_stat_totals_info", 
		"IP packets total tx/rx statistics, in packets(s)",
		METRIC_COUNTER, METRIC_VAL_UINT64, NULL, &ipstat_metric_ops,
		metric_label_new("reason", METRIC_VAL_STRING),
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
			warnx("%s", "ip_stat collection error");
		return (0);
	}
	/* Packet Totals RX/TX */
	metric_update(priv->total_tx_rx, "total-rx", priv->stats.ips_total);
	metric_update(priv->total_tx_rx, "total-consumed", priv->stats.ips_delivered);
	metric_update(priv->total_tx_rx, "total-tx", priv->stats.ips_localout);

	/* Following the order of declaration in ip_stat */
	metric_update(priv->pckts, "total-rx", priv->stats.ips_total);
	metric_update(priv->pckts, "bad-header-checksum", priv->stats.ips_badsum);
	metric_update(priv->pckts, "less-bytes-than-IPv4-header-length", priv->stats.ips_toosmall);
	metric_update(priv->pckts, "less-bytes-than-total-length-field", priv->stats.ips_tooshort);
	metric_update(priv->pckts, "bad-IP-header-length", priv->stats.ips_badhlen);
	metric_update(priv->pckts, "bad-options", priv->stats.ips_badoptions);
	metric_update(priv->pckts, "incorrect-version-number", priv->stats.ips_badvers);
	/* IP Fragments */
	metric_update(priv->frgmnt, "ip-fragments-received", priv->stats.ips_fragments);
	metric_update(priv->frgmnt, "ip-fragments-dropped", priv->stats.ips_fragdropped);
	metric_update(priv->frgmnt, "malformed-fragments-dropped", priv->stats.ips_badfrags);
	metric_update(priv->frgmnt, "fragments-dopped-after-timeout", priv->stats.ips_fragtimeout);
	metric_update(priv->pckts, "total-successfully-reassembled", priv->stats.ips_reassembled);
	metric_update(priv->pckts, "total-consumed", priv->stats.ips_delivered);
	metric_update(priv->pckts, "with-unknown-protocols", priv->stats.ips_noproto);
	metric_update(priv->pckts, "total-forwarded", priv->stats.ips_forward);
	metric_update(priv->pckts, "non-forwadable", priv->stats.ips_cantforward);
	metric_update(priv->pckts, "redirects-tx", priv->stats.ips_redirectsent);
	metric_update(priv->pckts, "total-tx", priv->stats.ips_localout);
	metric_update(priv->pckts, "sent-with-fabricated-ip-header", priv->stats.ips_rawout);
	metric_update(priv->pckts, "tx-dropped-no-buf", priv->stats.ips_odropped);
	metric_update(priv->pckts, "tx-dropped-noroute", priv->stats.ips_noroute);
	metric_update(priv->dgram, "tx-dgram-fragmented", priv->stats.ips_fragmented);
	metric_update(priv->frgmnt, "tx-fragments-created", priv->stats.ips_ofragments);
	metric_update(priv->dgram, "dgrams-cannot-be-fragmented", priv->stats.ips_cantfrag);
	metric_update(priv->frgmnt, "frags-dropped-no-memory", priv->stats.ips_rcvmemdrop);
	metric_update(priv->pckts, "more-bytes-than-max-packet-size", priv->stats.ips_toolong);
	metric_update(priv->pckts, "with-no-match-gif-found", priv->stats.ips_nogif);
	metric_update(priv->dgram, "dgrams-with-invalid-addr-on-header", priv->stats.ips_badaddr);
	metric_update(priv->dgram, "rx-dgram-software-checksummed", priv->stats.ips_inswcsum);
	metric_update(priv->dgram, "tx-dgram-software-checksummed", priv->stats.ips_outswcsum);
	metric_update(priv->pckts, "multicasts-for-unreg-groups", priv->stats.ips_notmember);
	metric_update(priv->pckts, "rx-on-wrong-interface", priv->stats.ips_wrongif);

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