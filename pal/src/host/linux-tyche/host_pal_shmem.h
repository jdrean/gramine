#pragma once

/* Simple bump allocator*/
#include <stddef.h>

#include "host_tyche_driver.h"
#include "pal_linux_defs.h"

#define USTACK_DEFAULT_SIZE (THREAD_STACK_SIZE / 4)

#include "pal_ecall_types.h"
typedef struct shmem_buffer_t {
    char* start;
    char* next_free;
    size_t size;
} shmem_buffer_t;

/* Shared memory info layout*/
typedef struct shmem_info_t {
    /* General information about the shared memory region*/
    uint64_t raw_start;
    uint64_t raw_size;
    size_t nb_threads;
    /* The enclave start args. */
    struct ecall_enclave_start* enclave_args;
    /* the ustacks*/
    void* ustacks;
    /* Bump allocator */
    shmem_buffer_t bump;
    /* Mmap allocator */
    shmem_buffer_t mmaps;
    /* The rpc queue memory region. */
    void* rpc_queue;
    /* Mmap region for futexes. */
    shmem_buffer_t futex_mmap;
} shmem_info_t;

shmem_info_t* init_shinfo(tyche_domain_t* domain, size_t nb_threads, uint64_t addr);
shmem_info_t* get_shmem_info(void);
void* shinfo_mmap(size_t size);
void* shinfo_futex_mmap(size_t size);
void* alloc_into_shinfo(size_t size);
void* copy_into_shinfo(void* src, size_t size);
char** copy_strarray_into_shinfo(char** arr, size_t size);
struct pal_topo_info* copy_topology_into_shinfo(struct pal_topo_info* topo);
int is_within_allocated_bump(uint64_t addr);
void tyche_pin_to_core(int core_id);
