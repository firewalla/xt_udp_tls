#ifndef _FIREWALLA_MEMORY_H_
#define _FIREWALLA_MEMORY_H_

#include <linux/slab.h>
#include <linux/types.h>


#define ALIGN_SIZE 16




int init_aligned_cache_pool(size_t size, size_t alignment);
void destroy_aligned_cache_pool(void);


int is_aligned(const void *ptr, size_t align_size);
int alloc_aligned_memory(void **orig_prt, void **aligned_prt, size_t size, size_t align_size);
void free_aligned_memory(void *ptr);


void *kmalloc_wrapper(size_t size, gfp_t flags);
void *kzalloc_wrapper(size_t size, gfp_t flags);
void *kmalloc_array_wrapper(size_t n, size_t size, gfp_t flags);
void *kmem_cache_alloc_wrapper(struct kmem_cache *cache, gfp_t flags);
void kmem_cache_free_wrapper(struct kmem_cache *cache, void *ptr);

void kfree_wrapper(void *ptr);

void print_memory_usage(void);

int create_mem_usage_proc_entry(void);
void remove_mem_usage_proc_entry(void);

void *alloc_memory_with_cache_pool(void);
void free_memory_with_cache_pool(void *ptr);

#endif /* _FIREWALLA_MEMORY_H_ */