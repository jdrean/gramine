/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#include "host_ecalls.h"
#include <errno.h>
#include "backend.h"
#include "common.h"
#include "enclave_api.h"
#include "host_internal.h"
#include "host_pal_shmem.h"
#include "pal_ecall_types.h"
#include "pal_rpc_queue.h"


static void pin_and_run(struct pal_enclave* enclave, int core_id) {
    tyche_pin_to_core(core_id);
    int ret = SUCCESS;

    do {
      ret = backend_td_vcpu_run(&(enclave->domain), core_id, 1 << gb_quantum);
      if (ret != SUCCESS) {
        log_error("Oupsy %d %d", errno, core_id);
        assert(0);
      }
      // The errno reports the exit reason from the driver.
      switch (errno) {
        case UNKNOWN:
          dispatch_tyche_ocall(core_id);
          break;
        case MEM_FAULT:
          log_error("Memory fault.");
          ret = FAILURE;
          break;
        case EXCEPTION:
          log_error("Received an exception");
          ret = FAILURE;
          break;
        case INTERRUPT:
          log_error("Received an interrupt");
          ret = FAILURE;
          break;
        case TIMER:
          continue;
          break;
        case REVOKED:
          log_error("Domain revoked");
          ret = FAILURE;
          break;
        default:
          log_error("weird value %d", errno);
          break;
      }
    } while(ret == SUCCESS);
    log_error("All done on thread %d (errno: %d)", core_id, errno);
}

int ecall_enclave_start(struct pal_enclave* enclave, char* libpal_uri, char* args,
                        size_t args_size, char* env,
                        size_t env_size, int parent_stream_fd, sgx_target_info_t* qe_targetinfo,
                        struct pal_topo_info* topo_info, struct pal_dns_host_conf* dns_conf,
                        bool edmm_enabled, void* reserved_mem_ranges,
                        size_t reserved_mem_ranges_size) {
    g_rpc_queue = NULL;
    int ret = SUCCESS;

    if (g_pal_enclave.rpc_thread_num > 0) {
        int ret = start_rpc(g_pal_enclave.rpc_thread_num);
        if (ret < 0) {
            /* failed to create RPC threads */
            return ret;
        }
        /* after this point, g_rpc_queue != NULL */
    }
    // TODO(aghosn): the index should be the cpuid rather than 0.
    struct ecall_enclave_start* start_args = &(get_shmem_info()->enclave_args[0]);
    start_args->libpal_uri               = libpal_uri;
    start_args->libpal_uri_len           = strlen(libpal_uri);
    start_args->args                     = args;
    start_args->args_size                = args_size;
    start_args->env                      = env;
    start_args->env_size                 = env_size;
    start_args->parent_stream_fd         = parent_stream_fd;
    start_args->qe_targetinfo            = qe_targetinfo;
    start_args->topo_info                = topo_info;
    start_args->dns_host_conf            = dns_conf;
    start_args->edmm_enabled             = edmm_enabled;
    start_args->reserved_mem_ranges      = reserved_mem_ranges;
    start_args->reserved_mem_ranges_size = reserved_mem_ranges_size;
    start_args->rpc_queue                = g_rpc_queue;
    //TODO: the enclave expects rbx to point to the TCS.
    //We also need to copy the arguments somewhere in shared memory.
    //TODO(aghosn) write a more complicated loop here to check why we exited.
    //This is the first thread, let's pin it.
    pin_and_run(enclave, 0);
    return 0;
}

int ecall_thread_start(int core_id) {
    pin_and_run(&g_pal_enclave, core_id);
    //return sgx_ecall(ECALL_THREAD_START, NULL);
}

int ecall_thread_reset(void) {
    //TODO(aghosn): figure out what to do.
    //return sgx_ecall(ECALL_THREAD_RESET, NULL);
}
