#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/cache.h>
#include <linux/jhash.h>
#include <linux/printk.h>
#include <linux/jiffies.h>
#include <linux/cpu.h>
#include <linux/random.h>
#include <linux/spinlock.h>
#include <linux/preempt.h>
#include <linux/netfilter.h>

#include "utils.h"
#include "quic_conversation.h"
#include "firewalla_memory.h"


// Statically allocated: guarantees the cacheline alignment declared on the struct
// and removes an allocation failure path for the array itself. The conversations
// it points at are still allocated in init_conversation_cache_buffer().
static struct conversation_shard g_conversation_shards[CONVERSATION_SHARD_COUNT];
static bool g_conversation_cache_ready;
// Randomised so a peer cannot craft connections whose 4-tuples all land in one
// shard and evict other handshakes' accumulated CRYPTO frames.
static u32 g_conversation_hash_seed __read_mostly;

// Map a connection to its shard. The key is direction-symmetric - swapping
// (src_addr,src_port) with (dst_addr,dst_port) yields the same value, because both
// XOR and addition are commutative - so both directions of a connection, and every
// Initial packet of one direction, land in the same shard regardless of CPU.
struct conversation_shard *conversation_shard_for(const struct packet_info *pinfo) {
	u32 ha, hb, h;

	// Returns NULL before init_conversation_cache_buffer() has succeeded and after
	// cleanup_conversation_cache_buffer(); callers then fall back to the per-CPU
	// scratch conversation and simply cannot carry state across packets.
	if (!g_conversation_cache_ready)
		return NULL;

	ha = jhash(pinfo->src_addr, 16, pinfo->src_port);
	hb = jhash(pinfo->dst_addr, 16, pinfo->dst_port);
	h = jhash_2words(ha ^ hb, ha + hb, g_conversation_hash_seed);

	return &g_conversation_shards[h & CONVERSATION_SHARD_MASK];
}

u32 conversation_shard_index(const struct conversation_shard *shard) {
	return (u32)(shard - g_conversation_shards);
}

void conversation_shard_lock(struct conversation_shard *shard) {
	// _bh rather than plain spin_lock: unlike the xt_tls payload cache, the
	// callers of this live in another translation unit, so the lock does not rely
	// on them having disabled softirqs. Nesting inside an existing bh-disabled
	// region is free.
	spin_lock_bh(&shard->lock);
}

void conversation_shard_unlock(struct conversation_shard *shard) {
	spin_unlock_bh(&shard->lock);
}

// Take the next slot in the ring. Reports in *evicted whether it was still holding
// a handshake that had not finished assembling, which is the only case that loses
// data. Status is deliberately not used to prefer a victim: find_conversation()
// matches on the 4-tuple plus the client's DCID, so a COMPLETE_CLIENT_HELLO entry
// keeps serving the SNI for the Initial packets of that one QUIC connection, and a
// later connection reusing the 4-tuple misses it and is parsed afresh.
static int conversation_next_slot(struct conversation_shard *shard, bool *evicted) {
	struct conversation *conv;
	int slot = shard->next;

	shard->next = (slot + 1) % CONVERSATION_SHARD_SIZE;
	if (shard->used < CONVERSATION_SHARD_SIZE)
		WRITE_ONCE(shard->used, shard->used + 1);

	conv = shard->list[slot];
	*evicted = conv->pinfo.family != 0 &&
	           conv->status == INCOMPLETE_CLIENT_HELLO;
	return slot;
}


int init_conversation_cache_buffer(void) {
	size_t cache_block_size = sizeof(struct crypto_frame_node);
	int s, j;

	// init cache pool for crypto_frame_node allocation
	if (init_aligned_cache_pool(cache_block_size, ALIGN_SIZE)) {
		pr_err("init_aligned_cache_pool failed.\n");
		return -ENOMEM;
	}

	get_random_bytes(&g_conversation_hash_seed, sizeof(g_conversation_hash_seed));

	for (s = 0; s < CONVERSATION_SHARD_COUNT; s++) {
		struct conversation_shard *shard = &g_conversation_shards[s];

		spin_lock_init(&shard->lock);
		for (j = 0; j < CONVERSATION_SHARD_SIZE; j++) {
			struct conversation *conv = kzalloc_wrapper(sizeof(struct conversation), GFP_KERNEL);
			if (!conv) {
				pr_err("Failed to allocate conversation shard=%d idx=%d\n", s, j);
				goto out_free_resources;
			}
			shard->list[j] = conv;
			conv->crypto_data = kzalloc_wrapper(MAX_CRYPTO_BUFFER_SIZE, GFP_KERNEL);
			if (!conv->crypto_data) {
				pr_err("Failed to allocate crypto data shard=%d idx=%d\n", s, j);
				goto out_free_resources;
			}
			conv->status = INCOMPLETE_CLIENT_HELLO;
			conv->hostname_len = 0;
			conv->completing_packet_number = 0;
			memset(conv->hostname, 0, MAX_DOMAIN_SIZE + 1);
			memset(&conv->pinfo, 0, sizeof(struct packet_info));
			memset(&conv->crypto_frames, 0, sizeof(struct crypto_frame_list));
		}
	}

	g_conversation_cache_ready = true;
	return 0;
out_free_resources:
	cleanup_conversation_cache_buffer();
	return -ENOMEM;
}

void cleanup_conversation_cache_buffer(void) {
	int s, j;

	// Close the cache to the match before freeing anything. Callers run either
	// before xt_register_matches() or after xt_unregister_matches(), so no packet
	// can be inside the parser at this point.
	g_conversation_cache_ready = false;

	for (s = 0; s < CONVERSATION_SHARD_COUNT; s++) {
		struct conversation_shard *shard = &g_conversation_shards[s];

		for (j = 0; j < CONVERSATION_SHARD_SIZE; j++) {
			struct conversation *conv = shard->list[j];
			struct crypto_frame_list *frame_list;
			struct crypto_frame_node *frame_node;

			if (!conv)
				continue;
			frame_list = &conv->crypto_frames;
			frame_node = frame_list->head;
			while (frame_node) {
				struct crypto_frame_node *next_node = frame_node->next;
				free_memory_with_cache_pool(frame_node);
				frame_node = next_node;
			}
			frame_list->head = NULL;
			frame_list->tail = NULL;
			frame_list->length = 0;
			if (conv->crypto_data) {
				kfree_wrapper(conv->crypto_data);
				conv->crypto_data = NULL;
			}
			kfree_wrapper(conv);
			shard->list[j] = NULL;
		}
		shard->next = 0;
		shard->used = 0;
	}

	destroy_aligned_cache_pool();
}


int compare_packet_info(struct packet_info *p1, struct packet_info *p2) {
	if (p1 == NULL || p2 == NULL) {
		return 1;
	}

	if (memcmp(p1->src_addr, p2->src_addr, 16) == 0 &&
	    memcmp(p1->dst_addr, p2->dst_addr, 16) == 0 &&
	    memcmp(&p1->src_port, &p2->src_port, 2) == 0 &&
	    memcmp(&p1->dst_port, &p2->dst_port, 2) == 0 &&
	    p1->dcid_len == p2->dcid_len &&
	    memcmp(p1->dcid, p2->dcid, p1->dcid_len) == 0) {
		pr_debug("packet_info is the same\n");
		return 0;
	}
	return 1;
}

void reset_conversation(struct conversation *conv) {
	struct crypto_frame_list *frame_list = NULL;
	struct crypto_frame_node *frame_node = NULL;
	if (!conv) {
		return;
	}
	frame_list = &conv->crypto_frames;
	frame_node = frame_list->head;
	while (frame_node) {
		struct crypto_frame_node *next_node = frame_node->next;
		free_memory_with_cache_pool(frame_node);
		frame_node = next_node;
	}

	conv->status = INCOMPLETE_CLIENT_HELLO;
	conv->hostname_len = 0;
	conv->completing_packet_number = 0;
	memset(conv->hostname, 0, MAX_DOMAIN_SIZE + 1);
	memset(&conv->pinfo, 0, sizeof(struct packet_info));
	memset(conv->crypto_data, 0, MAX_CRYPTO_BUFFER_SIZE);
	memset(&conv->crypto_frames, 0, sizeof(struct crypto_frame_list));
}

// Caller holds the shard lock (see conversation_shard_lock()).
struct conversation *find_conversation(struct conversation_shard *shard,
                                       struct packet_info *pinfo) {
	int i;

	// Nothing promoted into this shard yet - the common case for a shard that has
	// never seen a multi-packet handshake.
	if (shard->used == 0)
		return NULL;

	for (i = 0; i < shard->used; i++) {
		struct conversation *conv = shard->list[i];

		if (compare_packet_info(&conv->pinfo, pinfo) == 0) {
			pr_debug("found existing conversation shard[%u] index:%d\n",
			         conversation_shard_index(shard), i);
			return conv;
		}
	}

	pr_debug("no existing conversation in shard[%u]\n", conversation_shard_index(shard));
	return NULL;
}

// Promote a conversation into the shard so subsequent packets can find it. Caller
// holds the shard lock - which is also what makes the scratch swap below safe: no
// other CPU can be holding a pointer to the slot we are handing out, because every
// use of a shard entry happens under this same lock.
struct conversation *create_conversation(struct conversation_shard *shard,
    struct packet_info *pinfo, struct conversation **scratch_conv_ptr) {
	struct conversation *slot = NULL;
	bool evicted = false;
	int index;

	index = conversation_next_slot(shard, &evicted);
	slot = shard->list[index];

	// The slot the ring landed on still held a handshake that had not finished
	// assembling. This is the only case that loses data - a later Initial packet of
	// that connection will fail to find its conversation - and the signal to raise
	// CONVERSATION_SHARD_BITS or CONVERSATION_SHARD_SIZE.
	if (evicted) {
		if (slot->pinfo.family == NFPROTO_IPV4) {
			pr_debug("diag quic evicting in-flight conversation: shard=%u slot=%d victim saddr=%pI4 daddr=%pI4 sport=%u dport=%u\n",
				conversation_shard_index(shard), index,
				&slot->pinfo.src_addr, &slot->pinfo.dst_addr,
				slot->pinfo.src_port, slot->pinfo.dst_port);
		} else {
			pr_debug("diag quic evicting in-flight conversation: shard=%u slot=%d victim saddr=%pI6c daddr=%pI6c sport=%u dport=%u\n",
				conversation_shard_index(shard), index,
				&slot->pinfo.src_addr, &slot->pinfo.dst_addr,
				slot->pinfo.src_port, slot->pinfo.dst_port);
		}
	}
	pr_debug("creating conversation shard[%u] index:%d\n",
	         conversation_shard_index(shard), index);

	// Release the displaced slot's frames before it goes anywhere.
	reset_conversation(slot);

	if (scratch_conv_ptr && *scratch_conv_ptr) {
		// Swap: the scratch conversation (which carries the CRYPTO frames
		// accumulated for this packet) moves into the shard so subsequent packets
		// find it via find_conversation(); the freshly reset slot becomes this
		// CPU's new scratch buffer.
		struct conversation *promoted = *scratch_conv_ptr;

		shard->list[index] = promoted;
		*scratch_conv_ptr = slot;
		return promoted;
	}

	memcpy(&slot->pinfo, pinfo, sizeof(struct packet_info));
	return slot;
}

// Update conversation status and free all crypto frames, still keep hostname and pinfo
void update_conversation_status_and_free_frames(struct conversation *conv, enum conversation_status status) {
	struct crypto_frame_list *frame_list = NULL;
	struct crypto_frame_node *frame_node = NULL;
	if (!conv) {
		return;
	}

	frame_list = &conv->crypto_frames;
	frame_node = frame_list->head;
	while (frame_node) {
		struct crypto_frame_node *next_node = frame_node->next;
		free_memory_with_cache_pool(frame_node);
		frame_node = next_node;
	}

	memset(conv->crypto_data, 0, MAX_CRYPTO_BUFFER_SIZE);
	memset(&conv->crypto_frames, 0, sizeof(struct crypto_frame_list));

	conv->status = status;
}

void update_conversation_hostname(struct conversation *conv, const char *hostname, 
	size_t len) {
	if (!conv || !hostname) {
		return;
	}
	strncpy(conv->hostname, hostname, len);
	conv->hostname_len = len;
}

void print_packet_info(struct packet_info *pinfo) {
	if (!pinfo) {
		return;
	}
	if (pinfo->family == NFPROTO_IPV4) {
		pr_debug("saddr=%pI4, dstaddr=%pI4, sport=%u, dport=%u\n", 
			&pinfo->src_addr, &pinfo->dst_addr, pinfo->src_port, pinfo->dst_port);
	} else if (pinfo->family == NFPROTO_IPV6) {
		pr_debug("saddr=%pI6c, dstaddr=%pI6c, sport=%u, dport=%u\n", 
			&pinfo->src_addr, &pinfo->dst_addr, pinfo->src_port, pinfo->dst_port);
	}
}


struct crypto_frame_node *new_crypto_frame_node(size_t offset, size_t length) {
	struct crypto_frame_node *new_node = alloc_memory_with_cache_pool();
	if (new_node == NULL) {
		pr_err("Failed to allocate memory for new node\n");
		return NULL;
	}
	new_node->frame.offset = offset;
	new_node->frame.length = length;
	new_node->next = NULL;
	new_node->prev = NULL;

	return new_node;
}

// 
int is_first_crypto_frame_included(struct conversation *conv) {
	if (!conv || conv->crypto_frames.head == NULL) {
		return 0;
	}
	if (conv->crypto_frames.head->frame.offset == 0) {
		return 1;
	}
	return 0;
}

int is_frame_continuous_and_complete(struct conversation *conv) {

        struct crypto_frame_node *head = NULL;
        struct crypto_frame_node *node = NULL;
        struct crypto_frame_node *tail = NULL;
        size_t expected_offset = 0;


	if (!conv || conv->crypto_frames.head == NULL) {
		return 0;
	}

	head = conv->crypto_frames.head;
        node = head;
	// print_packet_info(&conv->pinfo);
	pr_debug("conv->crypto_frames.length:%zu\n", conv->crypto_frames.length);
	while (node) {
		pr_debug(
		    "expected_offset:%zu, node->frame.offset:%zu, "
		    "node->frame.length:%zu\n",
		    expected_offset, node->frame.offset,
		    node->frame.length);

		if (node->frame.offset != expected_offset) {
			pr_debug(
			    "frame is not continous, expected_offset:%zu, "
			    "node->frame.offset:%zu\n",
			    expected_offset, node->frame.offset);
			return 0;
		}
		expected_offset = node->frame.offset + node->frame.length;
		tail = node;
		node = node->next;
	}
	pr_debug("all frame is continous\n");

	if (conv->crypto_frames.client_hello_length == 0 && expected_offset >= 4) {
		// try to decode client_hello_length from current buffer
		// 1 byte for handshake type, 3 bytes for length field
		size_t client_hello_length = pntoh24(conv->crypto_data + 1);
		if (client_hello_length > MAX_CRYPTO_BUFFER_SIZE) {
			pr_debug("client_hello_length is too large\n");
			return 0;
		}
		conv->crypto_frames.client_hello_length = client_hello_length;
	}

	if (tail == NULL) {
		return 0;
	}

	// check if the last frame is complete
	pr_debug("tail->frame.offset:%zu, tail->frame.length:%zu\n",
	         tail->frame.offset, tail->frame.length);
	pr_debug("conv->crypto_frames.client_hello_length:%zu\n",
		conv->crypto_frames.client_hello_length);
	// clienthello header size(handshake type + the length of length field) + client_hello_length should be equal to 
	// the offset of the last frame + length of the last frame
	if (conv->crypto_frames.client_hello_length != 0 &&
	    conv->crypto_frames.client_hello_length + 4 ==
	        tail->frame.offset + tail->frame.length) {
		pr_debug("last frame is complete\n");
		return 1;
	}

	return 0;
}

void print_crypto_frame_list(struct crypto_frame_list *frame_list) {
#ifdef DEBUG
	struct crypto_frame_node *node = frame_list->head;
	while (node != NULL) {
		pr_debug("offset:%zu, length:%zu\n", node->frame.offset,
		         node->frame.length);
		node = node->next;
	}
#endif
}

void add_crypto_frame_to_list(struct crypto_frame_list *frame_list,
                              struct crypto_frame_node *new_node) {
	if (frame_list->head == NULL) {
		frame_list->head = new_node;
		frame_list->tail = new_node;
	} else {  // sort by offset
		struct crypto_frame_node *node = frame_list->head;
		while (node != NULL &&
		       node->frame.offset <
		           new_node->frame
		               .offset) {  // find the first node with offset
			                   // greater than new_node
			node = node->next;
		}
		if (node == NULL) {  // insert at tail
			frame_list->tail->next = new_node;
			new_node->prev = frame_list->tail;
			frame_list->tail = new_node;
		} else if (node->frame.offset ==
		           new_node->frame.offset) {  // ignore duplicate frame
			free_memory_with_cache_pool(new_node);
			return;
		} else if (node == frame_list->head) {  // insert at head
			new_node->next = frame_list->head;
			frame_list->head->prev = new_node;
			frame_list->head = new_node;
		} else {  // insert between node and node->prev
			new_node->next = node;
			new_node->prev = node->prev;
			if (new_node->prev != NULL) {
				new_node->prev->next = new_node;
			}
			node->prev = new_node;
		}
	}
	frame_list->length++;
	// pr_debug("add_crypto_frame_to_list, length:%zu\n", frame_list->length);
	// pr_debug("node frame list:\n");
	// print_crypto_frame_list(frame_list);
}

int add_frame_to_conversation(struct conversation *conv,
                              const u8 *frame_data, size_t offset,
                              size_t length) {

	struct crypto_frame_node *new_frame_node =
	    new_crypto_frame_node(offset, length);

	pr_debug("add_frame_to_conversation, offset:%zu, length:%zu\n", offset, length);

	if (!new_frame_node) {
		pr_err("Failed to allocate crypto frame node, offset:%zu, length:%zu\n", offset, length);
		return -1;
	}

	add_crypto_frame_to_list(&conv->crypto_frames,
	                         new_frame_node);

	// copy data to conv->crypto_data
	if (offset + length > MAX_CRYPTO_BUFFER_SIZE) {
		pr_debug(
		    "crypto data buffer is too small, need %zu bytes, but only "
		    "have %d bytes\n",
		    offset + length, MAX_CRYPTO_BUFFER_SIZE);
		return -1;
	}

	memcpy(conv->crypto_data + offset, frame_data, length);

	return 0;
}