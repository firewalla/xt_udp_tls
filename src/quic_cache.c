#include <linux/preempt.h>
#include <linux/percpu.h>
#include <linux/slab.h>

#include "quic_cache.h"
#include "utils.h"
#include "firewalla_memory.h"


static struct quic_cache __percpu *quic_cache_percpu = NULL;



int quic_cache_init(void) {
        int i;

        quic_cache_percpu = alloc_percpu(struct quic_cache);
        if (!quic_cache_percpu) {
                pr_err("quic_cache_init: failed to allocate per-cpu cache\n");
                return -ENOMEM;
        }

        for_each_possible_cpu(i) {
                struct quic_cache *cache = per_cpu_ptr(quic_cache_percpu, i);
                cache->udp_payload_buf = kmalloc_wrapper(UDP_PAYLOAD_BUFFER_SIZE, GFP_KERNEL);
                cache->decrypt_ctx = alloc_decrypt_context();
                if (!cache->udp_payload_buf || !cache->decrypt_ctx) {
                        pr_err("quic_cache_init: failed to allocate memory for per-cpu cache\n");
                        goto out_free_resources;
                }
                cache->scratch_conv = kzalloc_wrapper(sizeof(struct conversation), GFP_KERNEL);
                if (!cache->scratch_conv) {
                        pr_err("quic_cache_init: failed to allocate scratch conversation\n");
                        goto out_free_resources;
                }
                cache->scratch_conv->crypto_data = kzalloc_wrapper(MAX_CRYPTO_BUFFER_SIZE, GFP_KERNEL);
                if (!cache->scratch_conv->crypto_data) {
                        pr_err("quic_cache_init: failed to allocate scratch crypto_data\n");
                        goto out_free_resources;
                }
                cache->scratch_conv->status = INCOMPLETE_CLIENT_HELLO;
        }
        return 0;
out_free_resources:
        quic_cache_cleanup();
        return -ENOMEM;
}

void quic_cache_cleanup(void) {
        int i;
        if (!quic_cache_percpu) return;
        for_each_possible_cpu(i) {
                struct quic_cache *cache = per_cpu_ptr(quic_cache_percpu, i);
                if (cache->udp_payload_buf) kfree_wrapper(cache->udp_payload_buf);
                if (cache->decrypt_ctx) free_decrypt_context(cache->decrypt_ctx);
                if (cache->scratch_conv) {
                        struct crypto_frame_list *fl = &cache->scratch_conv->crypto_frames;
                        struct crypto_frame_node *fn = fl->head;
                        while (fn) {
                                struct crypto_frame_node *next = fn->next;
                                free_memory_with_cache_pool(fn);
                                fn = next;
                        }
                        if (cache->scratch_conv->crypto_data)
                                kfree_wrapper(cache->scratch_conv->crypto_data);
                        kfree_wrapper(cache->scratch_conv);
                        cache->scratch_conv = NULL;
                }
        }
        free_percpu(quic_cache_percpu);
        quic_cache_percpu = NULL;
}

struct quic_cache *get_quic_cache(void) {
        struct quic_cache *cache = NULL;
        cache = this_cpu_ptr(quic_cache_percpu);
        return cache;
}