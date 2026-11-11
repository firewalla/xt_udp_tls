#ifndef _QUIC_PARSER_H_
#define _QUIC_PARSER_H_

#include <linux/types.h>
#include "quic_conversation.h"


struct quic_header_info {
        u32 quic_version;
        u8 dcid[20];
        u8 dcid_len;
        u32 payload_len;
	u64 packet_number;
	u16 packet_number_len;
	// Points at the key_cache entry (hit or freshly derived) parse_quic_header()
	// resolved for this DCID/version. Per-CPU memory, valid for the lifetime of
	// processing this one packet. NULL only when parse_quic_header() itself failed.
	struct quic_packet_protection_info *protection_info;
};

struct quic_packet_protection_info {
        u8 key[16];
        u8 iv[12];
        u8 hp_key[16];
};


int process_quic_packets(const u_char *payload, size_t payload_length, struct packet_info *pinfo,
                        char *output_hostname, size_t output_hostname_len, int *record_hit);

// @shard: the conversation shard this connection maps to, already locked by the
// caller, or NULL when the conversation cache is unavailable. The lock has to span
// the whole call because the returned/created conversation is read and mutated
// throughout it.
int process_quic_packet(const u_char *payload, size_t payload_length, size_t *offset,
        struct conversation_shard *shard, struct packet_info *pinfo,
        char *output_hostname, size_t output_hostname_len, int *record_hit);
void log_parsed_result(struct packet_info *pinfo, const char *hostname);
int quic_parser_test(void);

#endif /* _QUIC_PARSER_H_ */