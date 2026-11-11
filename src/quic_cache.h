#ifndef _QUIC_CACHE_H_
#define _QUIC_CACHE_H_

#include "xt_tls.h"
#include "crypto.h"
#include "quic_conversation.h"
#include "quic_parser.h"


#define UDP_PAYLOAD_BUFFER_SIZE 4096

struct last_packet_cache {
        struct packet_info pinfo;
        u64 packet_number;
        char hostname[MAX_DOMAIN_SIZE + 1];
        size_t hostname_len;
        bool valid;
};

// A single derived-key entry, keyed by DCID + QUIC version.
struct key_cache_entry {
        u8 dcid[20];
        u8 dcid_len;
        u32 quic_version;
        struct quic_packet_protection_info protection_info;
        bool valid;
};

// Small per-CPU ring of derived keys, indexed by DCID rather than a single slot.
// A lone slot gets thrashed as soon as more than one QUIC handshake's Initial
// packets land on the same CPU at once (routine under RPS, since the shard the
// conversation cache uses and the CPU RPS picks are unrelated hashes) - every
// packet of every connection but the last-seen one would then re-run derive_keys()
// (several HKDF-SHA256 rounds), and do so while holding that connection's
// conversation shard lock. KEY_CACHE_SIZE entries make that collision rare instead
// of routine, matching the entry counts already used by the conversation/payload
// shard caches.
#define KEY_CACHE_SIZE 8

struct key_cache {
        struct key_cache_entry entries[KEY_CACHE_SIZE];
        int next; // next slot to overwrite (round robin, no per-entry recency)
};

struct quic_cache {
        char *udp_payload_buf;                  //used to store the un-linearized skb data
        struct decrypt_context *decrypt_ctx;    //used to store the decrypt context
        struct last_packet_cache last_pkt;      //per-cpu cache of the last processed packet
        struct key_cache key_cache;             //per-cpu cache of recently derived protection info, keyed by DCID
        struct conversation *scratch_conv;      //per-packet scratch buffer; avoids ring buffer allocation for non-fragmented flows
};


int quic_cache_init(void);
void quic_cache_cleanup(void);
struct quic_cache *get_quic_cache(void);


#endif /* _QUIC_CACHE_H_ */