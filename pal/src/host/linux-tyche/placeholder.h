#pragma once

/// Placeholder for now, we'll make the adjustements with TYCHE_DRIVER.

#include <asm-generic/int-ll64.h>

#include "sgx_arch.h"

#define SGX_IOC_ENCLAVE_CREATE               0
#define SGX_PAGE_MEASURE                     1
#define SGX_IOC_ENCLAVE_ADD_PAGES            2
#define SGX_IOC_ENCLAVE_RESTRICT_PERMISSIONS 3
#define SGX_IOC_ENCLAVE_MODIFY_TYPES         4
#define SGX_IOC_ENCLAVE_REMOVE_PAGES         5
#define SGX_IOC_ENCLAVE_INIT                 6
#define SGX_INVALID_SIG_STRUCT               7
#define SGX_INVALID_ATTRIBUTE                8
#define SGX_INVALID_MEASUREMENT              9
#define SGX_INVALID_SIGNATURE                10
#define SGX_INVALID_EINITTOKEN               11
#define SGX_INVALID_CPUSVN                   12

/**
 * struct sgx_enclave_create - parameter structure for the
 *                             %SGX_IOC_ENCLAVE_CREATE ioctl
 * @src:	address for the SECS page data
 */
struct sgx_enclave_create {
    __u64 src;
} __attribute__((__packed__));

struct sgx_enclave_add_pages {
    uint64_t offset;
    uint64_t src;
    size_t length;
    uint64_t secinfo;
    int flags;
    size_t count;
};

struct sgx_enclave_restrict_permissions {
    uint64_t offset;
    size_t length;
    uint64_t permissions;
    size_t count;
    int result;
};

struct sgx_enclave_modify_types {
    uint64_t offset;
    size_t length;
    uint64_t page_type;
    size_t count;
    int result;
};

struct sgx_enclave_remove_pages {
    uint64_t offset;
    size_t length;
    size_t count;
};

/**
 * struct sgx_enclave_init - parameter structure for the
 *                           %SGX_IOC_ENCLAVE_INIT ioctl
 * @addr:	address in the ELRANGE
 * @sigstruct:	address for the page data
 * @einittoken:	EINITTOKEN
 */
struct sgx_enclave_init {
    __u64 addr;
    __u64 sigstruct;
    __u64 einittoken;
} __attribute__((__packed__));
