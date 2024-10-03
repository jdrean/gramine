/* This file handles the creation of shared memory regions with the domain. 
 * It is responsible for copying all the start_args (one per possible thread)
 * and associated arguments/values. This is a workaround the fact that SGX preserves
 * access to all the untrusted memory (which we do not).*/

#include <asm-generic/mman-common.h>
#include <errno.h>
#include <linux/mman.h>
#include <stdint.h>
#include <stdlib.h>
#include "api.h"
#include "backend.h"
#include "host_pal_shmem.h"
#include "host_tyche_driver.h"
#include "pal.h"
#include "pal_ecall_types.h"
#include "pal_topology.h"
#include "sgx_arch.h"
#include "pal_rpc_queue.h"

#define _GNU_SOURCE
#include <sched.h>

#define BUMP_BUFFER_PAGES 20
#define EXTRA_MMAP_PAGES 56
#define FUTEX_MMAP_PAGES 8

/* The shared state layout info.*/
shmem_info_t* shinfo = NULL;

segment_type_t gb_segment_type = CONFIDENTIAL;

unsigned long gb_quantum = 10;


static int init_shmem(shmem_buffer_t* buff, size_t nb_pages) {
  buff->bitmap = calloc((nb_pages +7)/8, sizeof(uint8_t));
  if (buff->bitmap == NULL) {
    return -1;
  }
  memset(buff->bitmap, 0, (nb_pages + 7) / 8 * sizeof(uint8_t));
  return 0;
}

/* we compute the shared memory size with the following layout:
 * 1. The ecall_enclave_start arguments:
 *  a. We do one per thread allowed in the enclave.
 * 2. The ustacks
 *  a. We allocate one per enclave thread.
 * 3. The common information.
 *  a. Topology needs to be allocated.
 *    1. This requires a deep copy that's a bit annoying.
 *  b. The dns host cont needs to be allocated.
 *  c. The strings need to be allocated.
 *
 * 4. Seeing all the allocations we probably could benefit from a bump allocator.*/
shmem_info_t* init_shinfo(tyche_domain_t* domain, size_t nb_threads, uint64_t addr) {

  /* Compute how much we need.*/
  uint64_t s_estart = 0, s_ustacks = 0, s_bump = 0, s_mmap = 0, s_rpc_queue = 0;

  /* Summary of the shared state. */
  shinfo = malloc(sizeof(shmem_info_t));
  if (!shinfo) {
    log_error("Unable to allocate the shared memory info structure.");
    return NULL;
  }
  memset(shinfo, 0, sizeof(shmem_info_t));
  shinfo->nb_threads = nb_threads;

  /* The enclave start arguments. */
  shinfo->raw_size += nb_threads * (uint64_t) sizeof(struct ecall_enclave_start);
  /* memorize the end.*/
  shinfo->raw_size = ALIGN_UP(shinfo->raw_size, PT_PAGE_SIZE);
  assert(shinfo->raw_size % PT_PAGE_SIZE == 0);
  s_ustacks = shinfo->raw_size;

  shinfo->raw_size += nb_threads * USTACK_DEFAULT_SIZE;
  assert((shinfo->raw_size % PT_PAGE_SIZE) == 0);
  s_bump = shinfo->raw_size;

  /* Add the size of the bump.*/
  shinfo->raw_size += BUMP_BUFFER_PAGES * PT_PAGE_SIZE;
  assert((shinfo->raw_size % PT_PAGE_SIZE) == 0);

  /* Add the size of the extra mmap */
  s_mmap = shinfo->raw_size;
  shinfo->raw_size += EXTRA_MMAP_PAGES * PT_PAGE_SIZE;

  /* Add the size of rcp queue*/
  s_rpc_queue = shinfo->raw_size;
  shinfo->raw_size += ALIGN_UP(sizeof(rpc_queue_t), PRESET_PAGESIZE);

  /* Now allocate it for the domain.*/
  if (backend_td_mmap(domain, (void*) addr, shinfo->raw_size, PROT_READ | PROT_WRITE,
        MAP_FIXED_NOREPLACE | MAP_SHARED) != SUCCESS) {
    log_error("Unable to allocate the shared memory region %d", errno);
    return NULL;
  }

  /* Register the information */
  shinfo->raw_start = domain->mmaps.tail->virtoffset;
  shinfo->enclave_args = (struct ecall_enclave_start *)(shinfo->raw_start + s_estart);
  shinfo->ustacks = (void*)(shinfo->raw_start + s_ustacks);
  shinfo->bump.size = BUMP_BUFFER_PAGES * PT_PAGE_SIZE;
  shinfo->bump.start = (char*) (shinfo->raw_start + s_bump);
  shinfo->bump.next_free = shinfo->bump.start;
  shinfo->mmaps.start = (char*) (shinfo->raw_start + s_mmap);
  shinfo->mmaps.size = EXTRA_MMAP_PAGES * PT_PAGE_SIZE;
  assert(init_shmem(&(shinfo->mmaps), EXTRA_MMAP_PAGES) == 0);

  shinfo->rpc_queue = (void*) (shinfo->raw_start + s_rpc_queue);

  /* Allocate space for the futexes. Put it directly after the rest*/
  shinfo->futex_mmap.start = (uintptr_t) mmap((void*) (shinfo->raw_size + shinfo->raw_start),
      FUTEX_MMAP_PAGES * PRESET_PAGESIZE, PROT_READ| PROT_WRITE,
      MAP_PRIVATE | MAP_FIXED_NOREPLACE | MAP_POPULATE | MAP_LOCKED | MAP_ANONYMOUS,
      -1, 0);
  /// Map failed.
  if (shinfo->futex_mmap.start == ((void*) -1)) {
    log_error("Unable to map the futex mmap");
    return NULL;
  }
  if (!(shinfo->futex_mmap.start == (char*) (shinfo->raw_start + shinfo->raw_size))) {
    log_error("Big allocation mmap bug: We expected %p, but got %p | errno %d | size %d\n",
        shinfo->futex_mmap.start, 
        (char*) (shinfo->raw_start + shinfo->raw_size), errno,
        sizeof(shinfo->futex_mmap.start));
    // TODO: this is a hack to get back on track.
    shinfo->futex_mmap.start = (char*) (shinfo->raw_start + shinfo->raw_size);
  }
  assert(shinfo->futex_mmap.start == (char*) (shinfo->raw_start + shinfo->raw_size));
  shinfo->futex_mmap.size = FUTEX_MMAP_PAGES * PRESET_PAGESIZE;
  assert(init_shmem(&(shinfo->futex_mmap), FUTEX_MMAP_PAGES) == 0);

  /* Register the area with the driver.*/
  if (backend_td_register_mmap(domain, (void*) shinfo->futex_mmap.start,
        (size_t) shinfo->futex_mmap.size) != SUCCESS) {
    log_error("Unable to register the futex mmap region.");
    return NULL;
  }
  // Update the raw size so it gets registered correctly.
  shinfo->raw_size += FUTEX_MMAP_PAGES * PRESET_PAGESIZE;
  assert(shinfo->bump.start + shinfo->bump.size <= shinfo->mmaps.start);

  /* Directly register the region so we do not have to worry about it anymore. */
  if (backend_td_register_region(domain, (usize)shinfo->raw_start,
        shinfo->raw_size, MEM_READ | MEM_WRITE | MEM_SUPER, SHARED) != SUCCESS) {
   log_error("Unable to register the shared memory region."); 
   return NULL;
  }

  return shinfo;
}

shmem_info_t* get_shmem_info(void) {
  assert(shinfo != NULL);
  return shinfo;
}


// —————————————————————— Internal mmap implementation —————————————————————— //
static void set_bit(shmem_buffer_t* buff, size_t bit_index) {
    buff->bitmap[bit_index / 8] |= (1 << (bit_index % 8));
}

static void clear_bit(shmem_buffer_t* buff, size_t bit_index) {
    buff->bitmap[bit_index / 8] &= ~(1 << (bit_index % 8));
}

static bool is_bit_set(shmem_buffer_t* buff, size_t bit_index) {
    return buff->bitmap[bit_index / 8] & (1 << (bit_index % 8));
}

static void* memory_mmap(shmem_buffer_t* buff, size_t size) {
    size_t pages_needed = (size + PAGE_SIZE - 1) / PAGE_SIZE; // Round up to the nearest page count
    size_t contiguous_pages = 0;
    size_t start_page = 0;

    // Find a contiguous range of free pages
    for (size_t i = 0; i < (buff->size / PAGE_SIZE); i++) {
        if (!is_bit_set(buff, i)) {
            if (contiguous_pages == 0) {
                start_page = i;
            }
            contiguous_pages++;
            if (contiguous_pages == pages_needed) {
                break;
            }
        } else {
            contiguous_pages = 0;
        }
    }

    if (contiguous_pages < pages_needed) {
        log_error("Our mmap is too small!!!!\n");
        return NULL; // Not enough contiguous memory
    }

    // Mark the pages as allocated
    for (size_t i = start_page; i < start_page + pages_needed; i++) {
        set_bit(buff, i);
    }
    void* ptr = buff->start + (start_page * PAGE_SIZE);
    memset(ptr, 0, pages_needed * PAGE_SIZE);
    return ptr;
}

static void memory_munmap(shmem_buffer_t* buff, void* ptr, size_t size) {
    if (ptr == NULL || size == 0) return;

    size_t offset = (char*)ptr - buff->start;
    size_t start_page = offset / PAGE_SIZE;
    size_t pages_to_free = (size + PAGE_SIZE - 1) / PAGE_SIZE;

    // Mark the pages as free
    for (size_t i = start_page; i < start_page + pages_to_free; i++) {
        clear_bit(buff, i);
    }
}

// ———————————————————— The mmap API (normal and futex) ————————————————————— //

void* shinfo_mmap(size_t size) {
  void* ptr = memory_mmap(&(shinfo->mmaps), size);
  if (ptr == NULL) {
    log_error("Normal mmap failure");
  }
  return ptr;
}

void* shinfo_futex_mmap(size_t size) {
  void* ptr = memory_mmap(&(shinfo->futex_mmap), size);
  if (ptr == NULL) {
    log_error("futex mmap failure");
  }
  return ptr;
}

int shinfo_munmap(const void* addr, size_t size) {
  uint64_t vaddr = (uint64_t) addr;
  if (vaddr >= (uint64_t) shinfo->mmaps.start &&
      (vaddr+size) <= (uint64_t)(shinfo->mmaps.start + shinfo->mmaps.size)) {
    memory_munmap(&(shinfo->mmaps), (void*) vaddr, size);
    return 0;
  } else if (vaddr >= (uint64_t) shinfo->futex_mmap.start &&
      (vaddr + size) <= (uint64_t) (shinfo->futex_mmap.start + shinfo->futex_mmap.size)) {
    memory_munmap(&(shinfo->futex_mmap), (void*) vaddr, size);
    return 0;
  }
  log_error("Munmap of unknown address ...");
  return -1;
}

void * alloc_into_shinfo(size_t size) {
  assert(shinfo != NULL);
  void* result = NULL;
  size = ALIGN_UP(size, 8);
  if ((uint64_t)(shinfo->bump.next_free + size) >= 
      (uint64_t)(shinfo->bump.start + shinfo->bump.size)) {
    log_error("OOM in bump allocator for size %ld!", size);
    errno = ENOMEM;
    return NULL;
  }
  result = shinfo->bump.next_free;
  shinfo->bump.next_free += size;
  return result;
}

/* Copy the src value into the shared memory.
 * Return the address of the copied value.*/
void* copy_into_shinfo(void* src, size_t size) {
  assert(shinfo != NULL);
  void* result = alloc_into_shinfo(size);
  if (result == NULL) {
    return NULL;
  }
  memcpy(result, src, size);
  return result;
}

char** copy_strarray_into_shinfo(char** arr, size_t size) {
  assert(shinfo != NULL);
  assert(size > 0);
  assert(arr != NULL);
  size_t arr_size = size * sizeof(char*);
  char** result = (char**)(alloc_into_shinfo(arr_size));
  if (result == NULL) {
    goto failure;
  }
  for (size_t i = 0; i < size; i++) {
    /* include the '\0' */
    size_t str_size = strlen(arr[i]) + 1;
    result[i] = copy_into_shinfo(arr[i], str_size);
    if (result[i] == NULL) {
      goto failure;
    }
  }
  return result;
failure:
  log_error("OOM in strarray into shinfo");
  return NULL;
}

struct pal_topo_info* copy_topology_into_shinfo(struct pal_topo_info* topo) {
  assert(shinfo != NULL);
  assert(topo != NULL);
  struct pal_topo_info* c_topo =
    (struct pal_topo_info*) alloc_into_shinfo(sizeof(struct pal_topo_info));
  if (!c_topo) {
    goto failure;
  }
  /* Caches */
  c_topo->caches_cnt = topo->caches_cnt;
  size_t caches_size = topo->caches_cnt * sizeof(struct pal_cache_info);
  c_topo->caches = copy_into_shinfo(topo->caches, caches_size); 
  if (c_topo->caches == NULL) {
    goto failure;
  }

  /* Threads */
  c_topo->threads_cnt = topo->threads_cnt;
  size_t threads_size = topo->threads_cnt * sizeof(struct pal_cpu_thread_info);
  c_topo->threads = alloc_into_shinfo(threads_size);
  c_topo->threads = copy_into_shinfo(topo->threads, threads_size); 
  if (c_topo->threads == NULL) {
    goto failure;
  }

  /* Cores */
  c_topo->cores_cnt = topo->cores_cnt;
  size_t cores_size = topo->cores_cnt * sizeof(struct pal_cpu_core_info);
  c_topo->cores = copy_into_shinfo(topo->cores, cores_size);
  if (c_topo->cores == NULL) {
    goto failure;
  }

  /* Sockets */
  c_topo->sockets_cnt = topo->sockets_cnt;
  size_t sockets_size = topo->sockets_cnt * sizeof(struct pal_socket_info);
  c_topo->sockets = copy_into_shinfo(topo->sockets, sockets_size);
  if (c_topo->sockets == NULL) {
    goto failure;
  }

  /* Numa nodes*/
  c_topo->numa_nodes_cnt = topo->numa_nodes_cnt;
  size_t numa_nodes_size = topo->numa_nodes_cnt * sizeof(struct pal_numa_node_info);
  c_topo->numa_nodes = copy_into_shinfo(topo->numa_nodes, numa_nodes_size);
  if (c_topo->numa_nodes == NULL) {
    goto failure;
  }

  /* matrix */
  c_topo->numa_distance_matrix = copy_into_shinfo(topo->numa_distance_matrix, 
      sizeof(size_t) * topo->numa_nodes_cnt * topo->numa_nodes_cnt);
  if (c_topo->numa_distance_matrix == NULL) {
    goto failure;
  }
  return c_topo;
failure:
  return NULL;
}

int is_within_allocated_bump(uint64_t addr) {
  if (shinfo == NULL)
    return 0;
  return ((uint64_t) shinfo->bump.start <= addr && addr < (uint64_t) shinfo->bump.next_free);
}

void tyche_pin_to_core(int core_id) {
  // Figure out sched-affinity.
  int tid = 0;
  cpu_set_t mask;
  //assert(core_id < 4);

  // Clear the CPU set (initialize all bits to 0)
  memset(&mask, 0, sizeof(cpu_set_t));

  // Manually set CPU 0 (bit 0)
  ((unsigned long *)&mask)[0] |= (1UL << core_id);

  // Manually set CPU 1 (bit 1)

  // Set the CPU affinity for the current process
  if (sched_setaffinity(tid, sizeof(mask), &mask) == -1) {
      log_error("sched_setaffinity failed to pin to core %d", core_id);
      exit(-1);
  }
}
