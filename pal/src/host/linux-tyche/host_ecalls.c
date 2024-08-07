/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

#include "host_ecalls.h"
#include "backend.h"
#include "common.h"
#include "host_internal.h"
#include "pal_ecall_types.h"
#include "pal_rpc_queue.h"

int ecall_enclave_start(struct pal_enclave* enclave, char* libpal_uri, char* args,
                        size_t args_size, char* env,
                        size_t env_size, int parent_stream_fd, sgx_target_info_t* qe_targetinfo,
                        struct pal_topo_info* topo_info, struct pal_dns_host_conf* dns_conf,
                        bool edmm_enabled, void* reserved_mem_ranges,
                        size_t reserved_mem_ranges_size) {
    g_rpc_queue = NULL;

    if (g_pal_enclave.rpc_thread_num > 0) {
        int ret = start_rpc(g_pal_enclave.rpc_thread_num);
        if (ret < 0) {
            /* failed to create RPC threads */
            return ret;
        }
        /* after this point, g_rpc_queue != NULL */
    }

    //TODO: figure out how to implement that inside our implementation.
    struct ecall_enclave_start start_args = {
        .libpal_uri               = libpal_uri,
        .libpal_uri_len           = strlen(libpal_uri),
        .args                     = args,
        .args_size                = args_size,
        .env                      = env,
        .env_size                 = env_size,
        .parent_stream_fd         = parent_stream_fd,
        .qe_targetinfo            = qe_targetinfo,
        .topo_info                = topo_info,
        .dns_host_conf            = dns_conf,
        .edmm_enabled             = edmm_enabled,
        .reserved_mem_ranges      = reserved_mem_ranges,
        .reserved_mem_ranges_size = reserved_mem_ranges_size,
        .rpc_queue                = g_rpc_queue,
    };
    log_error("The first ecall");
    if (backend_td_vcpu_run(&(enclave->domain), sched_getcpu(), 0) != SUCCESS) {
      log_error("Oupsy");
      assert(0);
    }
    return 0;
}

int ecall_thread_start(void) {
    return sgx_ecall(ECALL_THREAD_START, NULL);
}

int ecall_thread_reset(void) {
    return sgx_ecall(ECALL_THREAD_RESET, NULL);
}
