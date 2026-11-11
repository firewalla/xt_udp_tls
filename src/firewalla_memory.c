#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/percpu.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/version.h>

#include "firewalla_memory.h"

#ifdef pr_fmt
#undef pr_fmt
#endif
#define pr_fmt(fmt) "[%s]:%s: " fmt, KBUILD_MODNAME, __func__

// The  for udp_tls aligned memory allocation
struct firewalla_cache_pool {
	struct kmem_cache *cache;
	size_t size;
	size_t align_size;
};

static struct firewalla_cache_pool *aligned_cache_pool = NULL;

DEFINE_PER_CPU(size_t, total_memory_used) = 0;


int init_aligned_cache_pool(size_t size, size_t alignment) {
	struct kmem_cache *cache = NULL;
	int ret = 0;

	if (aligned_cache_pool) {
		pr_info(
		    "aligned_cache_pool has already been initialized, destroy "
		    "it first.\n");
		return -EINVAL;
	}
	aligned_cache_pool =
	    kzalloc_wrapper(sizeof(struct firewalla_cache_pool), GFP_KERNEL);
	if (!aligned_cache_pool) {
		pr_err("Failed to allocate memory for aligned_cache_pool\n");
		return -ENOMEM;
	}
	cache = kmem_cache_create("aligned_cache", size, alignment,
	                          SLAB_HWCACHE_ALIGN, NULL);
	if (!cache) {
		pr_err("Failed to create kmem cache.\n");
		ret = -ENOMEM;
		goto out_free_aligned_cache_pool;
	}
	aligned_cache_pool->cache = cache;
	aligned_cache_pool->size = size;
	aligned_cache_pool->align_size = alignment;

	pr_info("Aligned cache pool initialized, size=%zu, align_size=%zu\n",
	        size, alignment);

	return 0;

out_free_aligned_cache_pool:
	kfree_wrapper(aligned_cache_pool);
	return ret;
}

void destroy_aligned_cache_pool(void) {
	if (!aligned_cache_pool) {
		pr_info(
		    "aligned_cache_pool has not been initialized, do "
		    "nothing.\n");
		return;
	}
	if (aligned_cache_pool->cache) {
		kmem_cache_destroy(aligned_cache_pool->cache);
	}

	kfree_wrapper(aligned_cache_pool);
	aligned_cache_pool = NULL;
}

void *alloc_memory_with_cache_pool(void) {
	void *ptr = NULL;
	ptr = kmem_cache_alloc_wrapper(aligned_cache_pool->cache, GFP_ATOMIC);
	if (!ptr) {
		pr_err("Failed to allocate memory from cache pool\n");
		return NULL;
	}
	return ptr;
}

void free_memory_with_cache_pool(void *ptr) {
	if (!ptr) {
		return;
	}
	kmem_cache_free_wrapper(aligned_cache_pool->cache, ptr);
	ptr = NULL;
}

/*
 * return 1 if aligned with align_size, otherwise return 0
 * */
int is_aligned(const void *ptr, size_t align_size) {
	unsigned long addr = (unsigned long)ptr;
	if ((addr & (align_size - 1)) == 0) {
		return 1;
	}
	return 0;
}

/*
 * return 0 on success, otherwise return -ENOMEM
 * */

int alloc_aligned_memory(void **orig_prt, void **aligned_prt, size_t size,
                         size_t align_size) {


	*orig_prt = kzalloc_wrapper(size + align_size - 1, GFP_KERNEL);
	if (!*orig_prt) {
		pr_err("Failed to allocate memory\n");
		return -ENOMEM;
	}
	*aligned_prt = PTR_ALIGN(*orig_prt, align_size);

	return 0;
}

void free_aligned_memory(void *ptr) {
	if (!ptr) {
		return;
	}
	kfree_wrapper(ptr);

	ptr = NULL;
}


void *kmalloc_wrapper(size_t size, gfp_t flags) {
	void *ptr = kmalloc(size, flags);
	if (ptr) {
		this_cpu_add(total_memory_used, ksize(ptr));
		pr_debug("allocated memory, size=%zu\n", ksize(ptr));
		// dump_stack();
	}
	return ptr;
}
void *kzalloc_wrapper(size_t size, gfp_t flags) {
	void *ptr = kzalloc(size, flags);
	if (ptr) {
		this_cpu_add(total_memory_used, ksize(ptr));
		pr_debug("allocated memory, size=%zu\n", ksize(ptr));
		// dump_stack();
	}
	return ptr;
}
void *kmalloc_array_wrapper(size_t n, size_t size, gfp_t flags) {
	void *ptr = kmalloc_array(n, size, flags);
	if (ptr) {
		this_cpu_add(total_memory_used, ksize(ptr));
		pr_debug("allocated memory, size=%zu\n", ksize(ptr));
		// dump_stack();
	}
	return ptr;
}


void kfree_wrapper(void *ptr) {
	if (ptr) {
		this_cpu_sub(total_memory_used, ksize(ptr));
		kfree(ptr);
		pr_debug("freed memory, size=%zu\n", ksize(ptr));
		// dump_stack();
	}
}

void *kmem_cache_alloc_wrapper(struct kmem_cache *cache, gfp_t flags) {
	void *ptr = kmem_cache_alloc(cache, flags);
	if (ptr) {
		this_cpu_add(total_memory_used, aligned_cache_pool->size); // ksize cann't get correct size for kmem_cache_alloc
		pr_debug("allocated memory from cache, size=%zu\n", aligned_cache_pool->size);
		// dump_stack();
	}
	return ptr;
}

void kmem_cache_free_wrapper(struct kmem_cache *cache, void *ptr) {
	if (ptr) {
		this_cpu_sub(total_memory_used, aligned_cache_pool->size);  // ksize cann't get correct size for kmem_cache_alloc
		kmem_cache_free(cache, ptr);
		pr_debug("freed memory from cache, size=%zu\n", aligned_cache_pool->size);
		// dump_stack();
	}
}

void print_memory_usage(void) {
	size_t total_used = 0;
	int cpu;
	for_each_possible_cpu(cpu) {
		total_used += per_cpu(total_memory_used, cpu);
	}
	pr_info("Memory usage: total_used=%zu\n", total_used);
}

// callback function when /proc file is read
static int memory_usage_show(struct seq_file *m, void *v)
{
	size_t total_used = 0;
	int cpu;
	for_each_possible_cpu(cpu) {
		total_used += per_cpu(total_memory_used, cpu);
	}

	seq_printf(m, "Memory usage: total_used=%zu\n", total_used);
	return 0;
}


// callback function when /proc file is opened
static int memory_usage_open(struct inode *inode, struct file *file)
{
    return single_open(file, memory_usage_show, NULL);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#define HAVE_PROC_OPS
#endif

#ifdef HAVE_PROC_OPS
static const struct proc_ops memory_usage_fops = {
    .proc_open = memory_usage_open,
    .proc_read = seq_read,
    .proc_release = seq_release,
    .proc_lseek = seq_lseek,
};
#else
// file operation struct for /proc/xt_udp_tls_memory_usage file
static const struct file_operations memory_usage_fops = {
    .owner = THIS_MODULE,
    .open = memory_usage_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = seq_release,
};
#endif


int create_mem_usage_proc_entry(void) {
	if (!proc_create("xt_udp_tls_memory_usage", 0444, NULL, &memory_usage_fops)) {
		pr_err("Failed to create /proc/xt_udp_tls_memory_usage entry\n");
		return -1;
	}
	return 0;
}

void remove_mem_usage_proc_entry(void) {
	remove_proc_entry("xt_udp_tls_memory_usage", NULL);
}