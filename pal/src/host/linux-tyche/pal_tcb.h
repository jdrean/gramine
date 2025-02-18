#pragma once

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#include "pal.h"
#include "sgx_arch.h"

struct untrusted_area {
    void* addr;
    size_t size;
    uint64_t in_use; /* must be uint64_t, because SET_ENCLAVE_TCB() currently supports only 8-byte
                      * types. TODO: fix this. */
    bool valid;
};

/*
 * Beside the classic thread control block (like ustack, thread, etc.) the TCB area is also used to
 * pass parameters needed during enclave or thread initialization. Some of them are thread specific
 * (like tcs_offset) and some of them are identical for all threads (like enclave_size).
 */
struct pal_enclave_tcb {
    PAL_TCB common;

    /* private to Linux-SGX PAL */
    uint64_t  enclave_size;
    uint64_t  tcs_offset;
    uint64_t  initial_stack_addr;
    uint64_t  tmp_rip;
    uint64_t  sig_stack_low;
    uint64_t  sig_stack_high;
    void*     ecall_return_addr;
    void*     ssa;
    sgx_pal_gpr_t* gpr;
    void*     exit_target;
    uintptr_t fsbase;
    void*     pre_ocall_stack;
    void*     ustack_top;
    void*     ustack;
    struct pal_handle_thread* thread;
    uint64_t  ocall_exit_called;
    uint64_t  thread_started;
    uint64_t  ready_for_exceptions;
    uint64_t  manifest_size;
    void*     heap_min;
    void*     heap_max;
    int*      clear_child_tid;
    uint64_t  core_id;
    struct untrusted_area untrusted_area_cache;
};

#ifndef DEBUG
extern uint64_t dummy_debug_variable;
#endif

#ifdef IN_ENCLAVE

static inline struct pal_enclave_tcb* pal_get_enclave_tcb(void) {
    return (struct pal_enclave_tcb*)pal_get_tcb();
}

#define GET_ENCLAVE_TCB(member)                                                                    \
    ({                                                                                             \
        struct pal_enclave_tcb* tmp;                                                               \
        uint64_t val;                                                                              \
        static_assert(sizeof(tmp->member) == 8, "pal_enclave_tcb member should have 8-byte type"); \
        __asm__("movq %%gs:%c1, %0"                                                                \
                : "=r"(val)                                                                        \
                : "i"(offsetof(struct pal_enclave_tcb, member))                                    \
                : "memory");                                                                       \
        (__typeof(tmp->member))val;                                                                \
    })
#define SET_ENCLAVE_TCB(member, value)                                                             \
    do {                                                                                           \
        struct pal_enclave_tcb* tmp;                                                               \
        static_assert(sizeof(tmp->member) == 8, "pal_enclave_tcb member should have 8-byte type"); \
        static_assert(sizeof(value) == 8, "only 8-byte type can be set to pal_enclave_tcb");       \
        __asm__("movq %0, %%gs:%c1"                                                                \
                :                                                                                  \
                : "ir"(value), "i"(offsetof(struct pal_enclave_tcb, member))                       \
                : "memory");                                                                       \
    } while (0)


__attribute_no_stack_protector
static inline void pal_set_tcb_stack_canary(uint64_t canary) {
    ((char*)&canary)[0] = 0; /* prevent C-string-based stack leaks from exposing the cookie */
    SET_ENCLAVE_TCB(common.stack_protector_canary, canary);
}

#else /* IN_ENCLAVE */

/* private to untrusted Linux PAL, unique to each untrusted thread */
typedef struct pal_host_tcb {
    struct pal_host_tcb* self;
    sgx_arch_tcs_t* tcs;           /* TCS page of SGX corresponding to thread, for EENTER */
    void* stack;                   /* bottom of stack, for later freeing when thread exits */
    void* alt_stack;               /* bottom of alt stack, for child thread to init alt stack */
    uint8_t is_in_aex_profiling;   /* non-zero if thread is currently doing AEX profiling */
    atomic_ulong eenter_cnt;       /* # of EENTERs, corresponds to # of ECALLs */
    atomic_ulong eexit_cnt;        /* # of EEXITs, corresponds to # of OCALLs */
    atomic_ulong aex_cnt;          /* # of AEXs, corresponds to # of interrupts/signals */
    atomic_ulong sync_signal_cnt;  /* # of sync signals, corresponds to # of SIGSEGV/SIGILL/.. */
    atomic_ulong async_signal_cnt; /* # of async signals, corresponds to # of SIGINT/SIGCONT/.. */
    uint64_t profile_sample_time;  /* last time sgx_profile_sample() recorded a sample */
    int32_t last_async_event;      /* last async signal, reported to the enclave on ocall return */
    int* start_status_ptr;         /* pointer to return value of clone_thread */
} PAL_HOST_TCB;

extern void pal_host_tcb_init(PAL_HOST_TCB* tcb, void* stack, void* alt_stack);

static inline PAL_HOST_TCB* pal_get_host_tcb(void) {
    PAL_HOST_TCB* tcb;
    __asm__("movq %%gs:%c1, %0\n"
            : "=r"(tcb)
            : "i"(offsetof(PAL_HOST_TCB, self))
            : "memory");
    return tcb;
}

extern bool g_sgx_enable_stats;
void update_and_print_stats(bool process_wide);
#endif /* IN_ENCLAVE */
