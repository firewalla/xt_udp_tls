
#include <asm/errno.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/udp.h>

#include "compat.h"
#include "crypto.h"
#include "firewalla_memory.h"
#include "hostset.h"
#include "quic_parser.h"
#include "utils.h"
#include "xt_tls.h"
#include "quic_conversation.h"
#include "quic_cache.h"

// The maximum number of host sets
static int max_host_sets = 100;

// uid/gid for hostset file
uid_t hostset_uid = 1000;
gid_t hostset_gid = 1000;



module_param(max_host_sets, int, S_IRUGO);
MODULE_PARM_DESC(max_host_sets, "host set table capacity (default 100)");

module_param(hostset_uid, int, S_IRUGO);
MODULE_PARM_DESC(hostset_uid, "uid for hostset file (default 1000)");

module_param(hostset_gid, int, S_IRUGO);
MODULE_PARM_DESC(hostset_gid, "gid for hostset file (default 1000)");

// The table of the host sets we use
static struct host_set **host_set_table;

enum test_result_type { TEST_SUCCESS, TEST_FAIL, TEST_NOT_RUN };

static enum test_result_type self_test_result =
    TEST_NOT_RUN;  // 0 - success, 1 - fail

/*
 * Searches through skb->data and try to extract SNI from a QUIC initial
 * package. A client handshake is preferred as the SNI field tells us what
 * domain the client wants to connect to.
 * return nagative value on error, 0 on success
 */
static int get_tls_hostname_udp(const struct sk_buff *skb, struct packet_info *pinfo, char *output_dest, 
                                size_t output_dest_len, unsigned short *port, unsigned int thoff, int *record_hit) {
	struct udphdr _udph, *udph = NULL;
	size_t udp_header_len;
	u8 *payload = NULL;
	size_t payload_len;
	size_t actual_payload_len;
	int ret;

	udph = skb_header_pointer(skb, thoff, sizeof(_udph), &_udph);
	if (!udph)
	    return -EPROTO;
	
	udp_header_len = sizeof(struct udphdr);

	payload_len = ntohs(udph->len) - udp_header_len;
	actual_payload_len =
	    skb->len - thoff - udp_header_len;

	if (actual_payload_len < payload_len) {
		// pr_debug("actual_payload_len < payload_len\n");
		return -EPROTO;
	}
	if (payload_len < 1200 || payload_len > UDP_PAYLOAD_BUFFER_SIZE) {
		// pr_debug("payload_len out of range\n");
		return -EPROTO;
	}

	*port = ntohs(udph->dest);

	pinfo->src_port = ntohs(udph->source);
	pinfo->dst_port = ntohs(udph->dest);

	print_packet_info(pinfo);

	// Softirqs off for everything below. All of get_quic_cache()'s contents are
	// per-CPU (the linearisation buffer `payload` may point into, the decrypt
	// context, the key cache and the scratch conversation) and they stay in use
	// until process_quic_packets() returns. Without this a rule in OUTPUT runs in
	// process context and could migrate cores mid-parse, leaving those pointers on
	// another CPU's data. It is a per-CPU preempt_count increment: no atomic, no
	// shared cacheline. The conversation shard lock is taken further in, inside
	// process_quic_packets().
	local_bh_disable();

	if (skb_is_nonlinear(skb)) {
		struct quic_cache *cache = get_quic_cache();
		pr_debug("skb is not linear, linearizing\n");
		payload = cache->udp_payload_buf;
		if (skb_copy_bits(skb, thoff + udp_header_len, payload, payload_len)) {
			pr_err("failed to copy bits from non-linear skb\n");
			local_bh_enable();
			return -EFAULT;
		}
	} else {
		payload =
		    skb->data + thoff + udp_header_len;
	}

	ret = process_quic_packets(payload, payload_len, pinfo, output_dest,
	                          output_dest_len, record_hit);

	local_bh_enable();

	return ret == 0 ? 0 : -EPROTO;
}

static bool udp_tls_mt(const struct sk_buff *skb, struct xt_action_param *par) {
	char parsed_host[MAX_DOMAIN_SIZE + 1];
	unsigned short port = 0;

	const struct xt_tls_info *info = par->matchinfo;

	int pattern_type = info->op_flags & (XT_TLS_OP_HOST | XT_TLS_OP_HOSTSET);

	bool invert = info->inversion_flags & (XT_TLS_OP_HOST | XT_TLS_OP_HOSTSET);

	bool match;
	struct packet_info pinfo = {0};
	int record_hit = 0;

	if (self_test_result != TEST_SUCCESS) {  // do not perfrom actually
		                                 // match if self-test failed
		return false;
	}

	memset(parsed_host, 0, MAX_DOMAIN_SIZE + 1);

	if (par->fragoff != 0) {
		pr_debug("Fragmented packet, cannot process\n");
		return false;
	}

	if (par->match->family == NFPROTO_IPV4) {
		struct iphdr *ip4h = ip_hdr(skb);
		if (ip4h->protocol != IPPROTO_UDP) {
			pr_debug("Non-UDP packet, ip4h->protocol=%d\n", ip4h->protocol);
			return false;
		}
		memcpy(pinfo.src_addr, &ip4h->saddr, sizeof(ip4h->saddr));
		memcpy(pinfo.dst_addr, &ip4h->daddr, sizeof(ip4h->daddr));
		pr_debug("IPv4 packet, src_addr=%pI4, dst_addr=%pI4\n", &ip4h->saddr, &ip4h->daddr);
	} else if (par->match->family == NFPROTO_IPV6) {
		struct ipv6hdr *ip6h = ipv6_hdr(skb);
		if (ip6h->nexthdr != IPPROTO_UDP) {
			pr_debug("Non-UDP packet, ip6h->nexthdr=%d\n", ip6h->nexthdr);
			return false;
		}

		memcpy(pinfo.src_addr, &ip6h->saddr, sizeof(ip6h->saddr));
		memcpy(pinfo.dst_addr, &ip6h->daddr, sizeof(ip6h->daddr));
		pr_debug("IPv6 packet, src_addr=%pI6, dst_addr=%pI6\n", &ip6h->saddr, &ip6h->daddr);
	} else {
		pr_err("Unsupported protocol family %d\n", par->match->family);
		return false;
	}
	pinfo.family = par->match->family;

	if (get_tls_hostname_udp(skb,  &pinfo, parsed_host,
	                        sizeof(parsed_host), &port, par->thoff, &record_hit) != 0 ||
	    parsed_host[0] == '\0') {
		return false;
	}
	
	pr_debug("Parsed domain: %s\n", parsed_host);
	if (info->log_msg) {
		// log_parsed_result(&pinfo, hostname);
		print_packet_info_and_hostname(skb, par, "FW_QUIC", parsed_host);
	}

	switch (pattern_type) {
		case XT_TLS_OP_HOST:
			match =
			    combo_match(info->host_or_set_name, parsed_host);
			pr_debug("combo_match: %s\n", match ? "true" : "false");
			break;
		case XT_TLS_OP_HOSTSET:
			match = hs_lookup(host_set_table[info->hostset_index],
			                  parsed_host, UDP, port, record_hit);
			pr_debug("hs_lookup, hostset_index=%d, match: %s\n", info->hostset_index,match ? "true" : "false");
			break;
		default: // only log message rule
			return false;
	}  // switch

	pr_debug("Domain matches: %s, invert: %s\n", match ? "true" : "false",
	         invert ? "true" : "false");

	if (invert) match = !match;
	if (match) pr_debug("Matched domain: %s\n", parsed_host);

	return match;
}

static int udp_tls_mt_check(const struct xt_mtchk_param *par) {
	__u16 proto;
	struct xt_tls_info *match_info = par->matchinfo;

	if (par->family == NFPROTO_IPV4) {
		proto = ((const struct ipt_ip *)par->entryinfo)->proto;
	} else if (par->family == NFPROTO_IPV6) {
		proto = ((const struct ip6t_ip6 *)par->entryinfo)->proto;
	} else {
		return -EINVAL;
	}

	if (proto != IPPROTO_UDP) {
		pr_info("Can be used only in combination with -p udp\n");
		return -EINVAL;
	}

	// If the rule contains --tls-hostset, try to find an existing matching
	// hostset table entry or allocate a new one
	if (match_info->op_flags & XT_TLS_OP_HOSTSET) {
		int i;
		bool found = false;

		for (i = 0; i < max_host_sets; i++) {
			found = !hs_is_free(host_set_table[i]) &&
			        strcmp(host_set_table[i]->name,
			               match_info->host_or_set_name) == 0;
			if (found) break;
		}  // for

		if (found) {
			hs_hold(host_set_table[i]);
		} else {
			int rc;
			for (i = 0; i < max_host_sets; i++) {
				found = hs_is_free(host_set_table[i]);
				if (found) break;
			}  // for
			if (!found) {
				pr_err(
				    "Cannot add a new hostset: the hostset "
				    "table is full\n");
				return -ENOMEM;
			}  // if
			rc = hs_init(host_set_table[i],
			             match_info->host_or_set_name);
			if (rc) return rc;
		}  // if

		match_info->hostset_index = i;
	}  // if

	return 0;
}

static void udp_tls_mt_destroy(const struct xt_mtdtor_param *par) {
	struct xt_tls_info *match_info = par->matchinfo;
#ifdef XT_TLS_DEBUG
	pr_info("tls_mt_destroy: match_info: op_flags=0x%X, hostset_index=%u\n",
	        match_info->op_flags, match_info->hostset_index);
#endif
	if (match_info->op_flags & XT_TLS_OP_HOSTSET) {
		hs_free(host_set_table[match_info->hostset_index]);
	}  // if
}  // tls_mt_destroy

static struct xt_match tls_mt_regs[] __read_mostly = {
    {
        .name = "udp_tls",
        .revision = 1,
        .family = NFPROTO_IPV4,
        .checkentry = udp_tls_mt_check,
        .destroy = udp_tls_mt_destroy,
        .match = udp_tls_mt,
        .matchsize = sizeof(struct xt_tls_info),
        .me = THIS_MODULE,
    },
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
    {
        .name = "udp_tls",
        .revision = 1,
        .family = NFPROTO_IPV6,
        .checkentry = udp_tls_mt_check,
        .destroy = udp_tls_mt_destroy,
        .match = udp_tls_mt,
        .matchsize = sizeof(struct xt_tls_info),
        .me = THIS_MODULE,
    },
#endif
};

static void destroy_host_set_table(void) {
	int i;
	if (!host_set_table)
		return ;
	for (i = 0; i < max_host_sets; i++) {
		if (host_set_table[i]) {
			hs_destroy(host_set_table[i]);
			kfree_wrapper(host_set_table[i]);
			host_set_table[i] = NULL;
		}
	}
	kfree_wrapper(host_set_table);
	host_set_table = NULL;
}

static int init_host_set_table(void) {
	int i;
	host_set_table =
	    kmalloc_wrapper(sizeof(struct host_set *) * max_host_sets, GFP_NOWAIT);
	if (!host_set_table) {
		pr_err("Cannot allocate memory for the host set table\n");
		return -ENOMEM;
	}  // if

	for (i = 0; i < max_host_sets; i++) {
		host_set_table[i] = kmalloc_wrapper(sizeof(struct host_set), GFP_NOWAIT);
		if (!host_set_table[i]) {
			pr_err("Cannot allocate memory for the host set %d\n", i);
			goto err_free_resources;
		}
		hs_zeroize(host_set_table[i]);
	}

	return 0;
err_free_resources:
	destroy_host_set_table();
	return -ENOMEM;
}



static int __init udp_tls_mt_init(void) {
	int rc;

	pr_info("registering kernel module...\n");

	init_max_MTU();
	pr_info("Max MTU of current system: %u\n", get_max_MTU());
	// The conversation cache's per-shard locks are initialised inside
	// init_conversation_cache_buffer() below.

	rc = quic_cache_init();
	if (rc) return rc;
	rc = init_conversation_cache_buffer();
	if (rc) return rc;


	//disable preempt to avoid context switch during quic_parser_test
	preempt_disable();
	rc = quic_parser_test();
	preempt_enable();
	if (rc == 0) {
		self_test_result = TEST_SUCCESS;
		pr_info("QUIC parser test passed\n");
	} else {
		self_test_result = TEST_FAIL;
		pr_err("QUIC parser test failed.\n");
	}
	// cleanup before create
	cleanup_procfs(KBUILD_MODNAME);
	create_procfs(KBUILD_MODNAME);

	rc = create_mem_usage_proc_entry();
	if (rc) return rc;

	rc = init_host_set_table();
	if (rc) return rc;
	pr_info("Host set table allocated (%u elements max)\n", max_host_sets);

	rc = xt_register_matches(tls_mt_regs, ARRAY_SIZE(tls_mt_regs));
	if (rc) return rc;

	pr_info("registered\n");
	return 0;
}

static void __exit udp_tls_mt_exit(void) {
	pr_info("deregistering kernel module...\n");

	xt_unregister_matches(tls_mt_regs, ARRAY_SIZE(tls_mt_regs));

	destroy_host_set_table();
	cleanup_procfs(KBUILD_MODNAME);

	pr_info("memory usage before quic_cache_cleanup:\n");
	print_memory_usage();
	quic_cache_cleanup();
	pr_info("memory usage after quic_cache_cleanup:\n");
	print_memory_usage();
	cleanup_conversation_cache_buffer();
	pr_info("memory usage after cleanup_conversation_cache_buffer:\n");
	print_memory_usage();

	remove_mem_usage_proc_entry();
	pr_info("deregistered\n");
}

module_init(udp_tls_mt_init);
module_exit(udp_tls_mt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("www.firewalla.com");
MODULE_DESCRIPTION("Xtables: TLS (SNI) matching for QUIC");
MODULE_ALIAS("ipt_udp_tls");
