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

	struct metric *ipckts, *ifrgmnt, *ofrgmnt;
	struct metric *opckts;
	struct metric *dpckts, *dfrgmnt, *ddgram;
	struct metric *dgram_chksm;
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


	priv->opckts = metric_new(r, "ip_tx_packets", 
		"IP outgoing packet statistics, in packet(s)",
		METRIC_COUNTER, METRIC_VAL_UINT64, NULL, &ipstat_metric_ops,
		metric_label_new("reason", METRIC_VAL_STRING),
	    NULL);

	priv->ipckts = metric_new(r, "ip_rx_packets", 
		"IP incoming packet statistics, in packet(s)",
		METRIC_COUNTER, METRIC_VAL_UINT64, NULL, &ipstat_metric_ops,
		metric_label_new("reason", METRIC_VAL_STRING),
	    NULL);

	priv->dpckts = metric_new(r, "ip_packet_diag_info", 
		"IP packet diagnpstics information, in packet(s)",
		METRIC_COUNTER, METRIC_VAL_UINT64, NULL, &ipstat_metric_ops,
		metric_label_new("reason", METRIC_VAL_STRING),
	    NULL);

	priv->ifrgmnt = metric_new(r, "ip_rx_fragments", 
		"IP incoming fragment information, in fragments(s)",
		METRIC_COUNTER, METRIC_VAL_UINT64, NULL, &ipstat_metric_ops,
		metric_label_new("reason", METRIC_VAL_STRING),
	    NULL);

	priv->ofrgmnt = metric_new(r, "ip_tx_fragments", 
		"IP created tx fragment information, in fragments(s)",
		METRIC_COUNTER, METRIC_VAL_UINT64, NULL, &ipstat_metric_ops,
		metric_label_new("reason", METRIC_VAL_STRING),
	    NULL);

	priv->dfrgmnt = metric_new(r, "ip_fragments_diag_info", 
		"IP fragments diagnostic information, in fragments(s)",
		METRIC_COUNTER, METRIC_VAL_UINT64, NULL, &ipstat_metric_ops,
		metric_label_new("reason", METRIC_VAL_STRING),
	    NULL);

	priv->dgram_chksm = metric_new(r, "dgram_checksum_info", 
		"Total datagrams software checksummed, in datagram(s)",
		METRIC_COUNTER, METRIC_VAL_UINT64, NULL, &ipstat_metric_ops,
		metric_label_new("reason", METRIC_VAL_STRING),
	    NULL);

	priv->ddgram = metric_new(r, "dgram_diag_info", 
		"Datagrams diagnostic information, in datagram(s)",
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

	/* Outgoing Packets */
	metric_update(priv->opckts, "total-tx", priv->stats.ips_localout);
	metric_update(priv->opckts, "redirects-tx", priv->stats.ips_redirectsent);
	metric_update(priv->opckts, "tx-dropped-no-buf", priv->stats.ips_odropped);
	metric_update(priv->opckts, "tx-dropped-noroute", priv->stats.ips_noroute);
	metric_update(priv->opckts, "sent-with-fabricated-ip-header", priv->stats.ips_rawout);
	metric_update(priv->opckts, "total-forwarded", priv->stats.ips_forward);
	/* Incoming Packets */
	metric_update(priv->ipckts, "total-consumed", priv->stats.ips_delivered);
	metric_update(priv->ipckts, "total-rx", priv->stats.ips_total);
	metric_update(priv->ipckts, "rx-on-wrong-interface", priv->stats.ips_wrongif);
	metric_update(priv->ipckts, "total-successfully-reassembled", priv->stats.ips_reassembled);
	/* IP Packet Diagnostics */
	metric_update(priv->dpckts, "with-unknown-protocols", priv->stats.ips_noproto);
	metric_update(priv->dpckts, "bad-header-checksum", priv->stats.ips_badsum);
	metric_update(priv->dpckts, "less-bytes-than-IPv4-header-length", priv->stats.ips_toosmall);
	metric_update(priv->dpckts, "packets-too-short", priv->stats.ips_tooshort);
	metric_update(priv->dpckts, "bad-ip-header-length", priv->stats.ips_badhlen);
	metric_update(priv->dpckts, "less-bytes-than-total-length-field", priv->stats.ips_badlen);
	metric_update(priv->dpckts, "bad-options", priv->stats.ips_badoptions);
	metric_update(priv->dpckts, "incorrect-version-number", priv->stats.ips_badvers);
	metric_update(priv->dpckts, "non-forwadable", priv->stats.ips_cantforward);
	metric_update(priv->dpckts, "more-bytes-than-max-packet-size", priv->stats.ips_toolong);
	metric_update(priv->dpckts, "with-no-match-gif-found", priv->stats.ips_nogif);
	metric_update(priv->dpckts, "multicasts-for-unreg-groups", priv->stats.ips_notmember);
	/* IP Fragments */
	metric_update(priv->ifrgmnt, "ip-received", priv->stats.ips_fragments);
	metric_update(priv->ofrgmnt, "tx-created", priv->stats.ips_ofragments);
	metric_update(priv->dfrgmnt, "ip-dropped", priv->stats.ips_fragdropped);
	metric_update(priv->dfrgmnt, "malformed-dropped", priv->stats.ips_badfrags);
	metric_update(priv->dfrgmnt, "dropped-after-timeout", priv->stats.ips_fragtimeout);
	metric_update(priv->dfrgmnt, "dropped-no-memory", priv->stats.ips_rcvmemdrop);
	/* Datagram Info */
	metric_update(priv->ddgram, "with-tx-fragmented", priv->stats.ips_fragmented);
	metric_update(priv->ddgram, "cannot-be-fragmented", priv->stats.ips_cantfrag);
	metric_update(priv->ddgram, "with-invalid-addr-on-header", priv->stats.ips_badaddr);
	metric_update(priv->dgram_chksm, "rx-dgrams", priv->stats.ips_inswcsum);
	metric_update(priv->dgram_chksm, "tx-dgrams", priv->stats.ips_outswcsum);
	/* Clear old values */
	metric_clear_old_values(priv->opckts);
	metric_clear_old_values(priv->ipckts);
	metric_clear_old_values(priv->dpckts);
	metric_clear_old_values(priv->ifrgmnt);
	metric_clear_old_values(priv->ofrgmnt);
	metric_clear_old_values(priv->dfrgmnt);
	metric_clear_old_values(priv->ddgram);
	metric_clear_old_values(priv->dgram_chksm);

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