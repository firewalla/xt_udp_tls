#ifndef _QUIC_CONVERSATION_H_
#define _QUIC_CONVERSATION_H_

#include <linux/types.h>
#include <linux/cache.h>
#include <linux/spinlock.h>
#include "xt_tls.h"

// The conversation cache is a flat array of CONVERSATION_SHARD_COUNT shards, each
// holding CONVERSATION_SHARD_SIZE entries behind its own lock. A connection is
// mapped to a shard by a direction-symmetric hash of its 4-tuple, so every packet
// of a QUIC handshake reaches the same shard no matter which CPU handles it.
//
// This replaces a per-CPU layout (one ring per CPU, bucketed by src_port & 3).
// A QUIC ClientHello that spans several Initial packets - routine now that
// post-quantum key shares push it past one datagram - lost all its accumulated
// CRYPTO frames whenever RPS, an ifb reinjection or a CPU-affinity change moved the
// following packets to another core. The SNI then never got parsed and the
// connection slipped through unmatched. Correctness no longer depends on CPU
// pinning; it is now only a locality optimisation.
//
// Same geometry as the TCP-side payload cache in xt_tls, deliberately: 64 x 8 =
// 512 entries, which is exactly what the old nr_cpus * 4 * 32 per-CPU layout
// allocated on a quad-core box, so memory is unchanged (~2.3 MiB). Many shards
// keeps simultaneous hits on one shard rare; few entries per shard keeps the
// locked scan short.
#define CONVERSATION_SHARD_BITS         6
#define CONVERSATION_SHARD_COUNT        (1 << CONVERSATION_SHARD_BITS)
#define CONVERSATION_SHARD_MASK         (CONVERSATION_SHARD_COUNT - 1)
#define CONVERSATION_SHARD_SIZE         8
#define CONVERSATION_CACHE_SIZE         (CONVERSATION_SHARD_COUNT * CONVERSATION_SHARD_SIZE)
#define MAX_CRYPTO_BUFFER_SIZE          4096 //base on rfc9000 at least need cache 4096 bytes for out-of-order crypto data

struct packet_info {
	u8 src_addr[16];
	u8 dst_addr[16];
	u16 src_port;
	u16 dst_port;
	// The client's Destination Connection ID from the Initial header. Part of the
	// key alongside the 4-tuple: a new QUIC connection that reuses a 4-tuple picks
	// a fresh random DCID, so it can never be served the SNI (or ERROR status) a
	// previous connection on that 4-tuple left behind in the caches. Not used by
	// conversation_shard_for(), which hashes the 4-tuple only.
	u8 dcid_len;
	u8 dcid[20];
	u8 family;
};

struct crypto_frame {
	size_t offset;
	size_t length;
};

struct crypto_frame_node {
	struct crypto_frame frame;
	struct crypto_frame_node *next;
	struct crypto_frame_node *prev;
};

struct crypto_frame_list {
	struct crypto_frame_node *head;
	struct crypto_frame_node *tail;
	size_t length;
	size_t client_hello_length;
};


enum conversation_status {
	ERROR,
	INCOMPLETE_CLIENT_HELLO, 		// client hello is incomplete, need more data
	COMPLETE_CLIENT_HELLO 			// complete
};

struct conversation {
	// ---- HOT: read while scanning a shard, grouped at the front so one cacheline
	// answers a non-matching entry. Do not interleave anything cold into here.
	struct packet_info pinfo;
	enum conversation_status status;

	// ---- COLD: only touched once an entry actually matches a packet.
	struct crypto_frame_list crypto_frames;
	u8 *crypto_data;           // buffer to store crypto data, minimum size is MAX_CRYPTO_BUFFER_SIZE
	char hostname[MAX_DOMAIN_SIZE + 1];
	size_t hostname_len;
	// packet number of the packet that completed SNI parsing (for multi-rule record_hit correctness)
	u64 completing_packet_number;
};

// One shard: its entries plus the lock guarding them. Cacheline-aligned so two
// shards worked on by two CPUs never share a line.
//
// Used as a ring: inserts rotate through the slots in index order and overwrite
// whatever is there, so an entry survives CONVERSATION_SHARD_SIZE further inserts
// into its own shard. No per-entry timestamp or scan for a "best" victim - the
// shard is full within moments of module load and stays that way, so any such
// scheme would only ever pay off during warm-up.
struct conversation_shard {
	spinlock_t lock;
	struct conversation *list[CONVERSATION_SHARD_SIZE];
	// Next slot to overwrite.
	int next;
	// High-water mark of slots ever written. Only ever grows, and because `next`
	// starts at 0 the written slots are exactly [0, used). Lets the lookup skip a
	// shard that has never cached anything without dereferencing any entry.
	int used;
} ____cacheline_aligned_in_smp;

int compare_packet_info(struct packet_info *p1, struct packet_info *p2);

// Resolve the shard a connection belongs to. Cheap and lock-free; the caller then
// locks it around every use of the conversations inside.
struct conversation_shard *conversation_shard_for(const struct packet_info *pinfo);
u32 conversation_shard_index(const struct conversation_shard *shard);

// The lock must be held across the *whole* use of a returned conversation, not
// just the lookup: a concurrent create_conversation() on the same shard can swap
// an entry out into another CPU's scratch buffer, so a pointer obtained earlier
// and used after unlocking would be reading a buffer that CPU now owns.
void conversation_shard_lock(struct conversation_shard *shard);
void conversation_shard_unlock(struct conversation_shard *shard);

struct conversation *find_conversation(struct conversation_shard *shard,
                                       struct packet_info *pinfo);

struct conversation *create_conversation(struct conversation_shard *shard,
    struct packet_info *pinfo, struct conversation **scratch_conv_ptr);

int is_first_crypto_frame_included(struct conversation *conv);


void update_conversation_status_and_free_frames(struct conversation *conv, enum conversation_status status);
void reset_conversation(struct conversation *conv);
int is_frame_continuous_and_complete(struct conversation *conv);

int add_frame_to_conversation(struct conversation *conv,
                              const u8 *frame_data, size_t offset,
                              size_t length);
void update_conversation_hostname(struct conversation *conv, const char *hostname, 
			size_t len);

int init_conversation_cache_buffer(void);
void cleanup_conversation_cache_buffer(void);

void print_packet_info(struct packet_info *pinfo);
void print_crypto_frame_list(struct crypto_frame_list *frame_list);

#endif /* _QUIC_CONVERSATION_H_ */