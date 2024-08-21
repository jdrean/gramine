#include <asm-generic/errno-base.h>
#include <asm-generic/mman-common.h>
#include <asm/errno.h>
#include <errno.h>
#include <stdint.h>

#include "backend.h"
#include "hex.h"
#include "host_pal_shmem.h"
#include "host_tyche_driver.h"
#include "log.h"
#include "placeholder.h"
#include "host_internal.h"
#include "linux_utils.h"
#include "pal_sgx.h"
#include "sdk_tyche_types.h"
#include "sgx_arch.h"
#include "tyche_capabilities_types.h"
#include "unix_error.h"

static int g_isgx_device = -1;

static void*  g_zero_pages      = NULL;
static size_t g_zero_pages_size = 0;

int read_enclave_token(int token_file, sgx_arch_token_t* out_token) {
    struct stat stat;
    int ret;
    ret = DO_SYSCALL(fstat, token_file, &stat);
    if (ret < 0)
        return ret;

    if (stat.st_size != sizeof(sgx_arch_token_t)) {
        log_error("Token size does not match.");
        return -EINVAL;
    }

    int bytes = DO_SYSCALL(read, token_file, out_token, sizeof(sgx_arch_token_t));
    if (bytes < 0) {
        return bytes;
    } else if (bytes != sizeof(sgx_arch_token_t)) {
        log_error("Short read while reading token file.");
        return -EINVAL;
    }

    char hex[64 * 2 + 1]; /* large enough to hold any of the below fields */
#define BYTES2HEX(bytes) (bytes2hex(bytes, sizeof(bytes), hex, sizeof(hex)))
    log_debug("Read token:");
    log_debug("    valid:                 0x%08x",   out_token->body.valid);
    log_debug("    attr.flags:            0x%016lx", out_token->body.attributes.flags);
    log_debug("    attr.xfrm:             0x%016lx", out_token->body.attributes.xfrm);
    log_debug("    mr_enclave:            %s",       BYTES2HEX(out_token->body.mr_enclave.m));
    log_debug("    mr_signer:             %s",       BYTES2HEX(out_token->body.mr_signer.m));
    log_debug("    LE cpu_svn:            %s",       BYTES2HEX(out_token->cpu_svn_le.svn));
    log_debug("    LE isv_prod_id:        %02x",     out_token->isv_prod_id_le);
    log_debug("    LE isv_svn:            %02x",     out_token->isv_svn_le);
    log_debug("    LE masked_misc_select: 0x%08x",   out_token->masked_misc_select_le);
    log_debug("    LE attr.flags:         0x%016lx", out_token->attributes_le.flags);
    log_debug("    LE attr.xfrm:          0x%016lx", out_token->attributes_le.xfrm);
#undef BYTES2HEX

    return 0;
}

static int get_optional_sgx_features(uint64_t xfrm, uint64_t xfrm_mask, uint64_t* out_xfrm) {
    /* see also sgx_get_token.py:get_optional_sgx_features(), used for legacy non-FLC machines */
    const struct {
        uint64_t bits;
        const struct {
            uint32_t leaf;
            uint32_t subleaf;
            uint32_t reg;
            uint32_t bit;
        } cpuid;
    } xfrm_flags[] = {
        /* for mapping of CPUID leaves to CPU features, see libos/src/arch/x86_64/libos_cpuid.c */
        {SGX_XFRM_AVX,    { .leaf = FEATURE_FLAGS_LEAF,          .subleaf = 0, .reg = CPUID_WORD_ECX, .bit = 28 }},
        {SGX_XFRM_MPX,    { .leaf = EXTENDED_FEATURE_FLAGS_LEAF, .subleaf = 0, .reg = CPUID_WORD_EBX, .bit = 14 }},
        {SGX_XFRM_AVX512, { .leaf = EXTENDED_FEATURE_FLAGS_LEAF, .subleaf = 0, .reg = CPUID_WORD_EBX, .bit = 16 }},
        {SGX_XFRM_PKRU,   { .leaf = EXTENDED_FEATURE_FLAGS_LEAF, .subleaf = 0, .reg = CPUID_WORD_ECX, .bit = 3 }},
        {SGX_XFRM_AMX,    { .leaf = EXTENDED_FEATURE_FLAGS_LEAF, .subleaf = 0, .reg = CPUID_WORD_EDX, .bit = 24 }},
    };

    *out_xfrm = xfrm;
    for (size_t i = 0; i < ARRAY_SIZE(xfrm_flags); i++) {
        /* check if SIGSTRUCT.ATTRIBUTEMASK.XFRM doesn't care whether an optional CPU feature is
         * enabled or not (XFRM mask should completely unset these bits) */
        if ((xfrm_flags[i].bits & xfrm_mask) == 0) {
            /* set CPU feature if current system supports it (for performance) */
            uint32_t values[4];
            cpuid(xfrm_flags[i].cpuid.leaf, xfrm_flags[i].cpuid.subleaf, values);
            if (values[xfrm_flags[i].cpuid.reg] & (1u << xfrm_flags[i].cpuid.bit))
                *out_xfrm |= xfrm_flags[i].bits;
        }
    }

    return 0;
}

int create_dummy_enclave_token(sgx_sigstruct_t* sig, sgx_arch_token_t* out_token) {
    memset(out_token, 0, sizeof(*out_token));
    memcpy(&out_token->body.attributes, &sig->attributes, sizeof(sgx_attributes_t));
    out_token->masked_misc_select_le = sig->misc_select;

    return get_optional_sgx_features(sig->attributes.xfrm, sig->attribute_mask.xfrm,
                                     &out_token->body.attributes.xfrm);
}

int read_enclave_sigstruct(int sigfile, sgx_sigstruct_t* sig) {
    struct stat stat;
    int ret;
    ret = DO_SYSCALL(fstat, sigfile, &stat);
    if (ret < 0)
        return ret;

    if ((size_t)stat.st_size != sizeof(sgx_sigstruct_t)) {
        log_error("size of sigstruct size does not match");
        return -EINVAL;
    }

    ret = read_all(sigfile, sig, sizeof(sgx_sigstruct_t));
    if (ret < 0)
        return ret;

    return 0;
}

bool is_wrfsbase_supported(void) {
    uint32_t cpuinfo[4];
    cpuid(EXTENDED_FEATURE_FLAGS_LEAF, 0, cpuinfo);

    if (!(cpuinfo[1] & 0x1)) {
        log_error(
            "{RD,WR}{FS,GS}BASE instructions are not permitted on this platform. Please check the "
            "instructions under \"Building with SGX support\" from Gramine documentation.");
        return false;
    }

    return true;
}

static uint64_t compute_pages(uint64_t base, uint64_t size)
{
  uint64_t end = base + size;
  level_t levels[3] = {PT_PML4, PT_PGD, PT_PMD};
  unsigned long pages[3] = {0, 0, 0};

  /* Go through all levels using the higher level to compute nb pages*/
  for (int i = 0; i < 3; i++) {
    index_t s_idx = x86_64_get_index(base, levels[i], &x86_64_profile);
    index_t e_idx =  x86_64_get_index(end, levels[i], &x86_64_profile);
    if (i == 0) {
      pages[i] = e_idx - s_idx + 1;
      continue;
    }
    /* the formula is simple: how many entries times 512 and substract partial
     * pages for the first and last index.*/
    pages[i] = (pages[i-1] * ((unsigned long) x86_64_profile.nb_entries))
      - ((unsigned long) s_idx)
      - (((unsigned long) x86_64_profile.nb_entries) - ((unsigned long) e_idx)) + 1;
  }
  /* 1 for root, then how many entries in PML4, + how many entries in PGD etc.*/
  return 1 + pages[0] + pages[1] + pages[2];
}

int create_enclave(sgx_arch_secs_t* secs, sgx_arch_token_t* token, unsigned long nb_threads) {
    assert(secs->size && IS_POWER_OF_2(secs->size));
    assert(IS_ALIGNED(secs->base, secs->size));
    assert(secs->domain != NULL);
    int ret = 0;

    secs->ssa_frame_size = SSA_FRAME_SIZE / g_page_size; /* SECS expects SSA frame size in pages */
    secs->misc_select    = token->masked_misc_select_le;
    memcpy(&secs->attributes, &token->body.attributes, sizeof(sgx_attributes_t));

    /* Do not initialize secs->mr_signer and secs->mr_enclave here as they are
     * not used by ECREATE to populate the internal SECS. SECS's mr_enclave is
     * computed dynamically and SECS's mr_signer is populated based on the
     * SIGSTRUCT during EINIT (see pp21 for ECREATE and pp34 for
     * EINIT in https://software.intel.com/sites/default/files/managed/48/88/329298-002.pdf). */

    uint64_t request_mmap_addr = secs->base;
    uint64_t request_mmap_size = secs->size;

#ifndef CONFIG_SGX_DRIVER_OOT
    /* newer DCAP/in-kernel SGX drivers allow starting enclave address space with non-zero;
     * the below trick to start from MMAP_MIN_ADDR is to avoid vm.mmap_min_addr==0 issue */
    if (request_mmap_addr < MMAP_MIN_ADDR) {
        request_mmap_size -= MMAP_MIN_ADDR - request_mmap_addr;
        request_mmap_addr  = MMAP_MIN_ADDR;
    }
#endif

    /* Initialize the domain structure */
    dll_init_list(&(secs->domain->shared_regions));
    dll_init_list(&(secs->domain->mmaps));
    dll_init_list(&(secs->domain->pipes));

    /* Create the domain with the selected backend.*/
    if (backend_td_create(secs->domain) != SUCCESS) {
      log_error("Unable to create the enclave : %s", unix_strerror(ENODEV));
      return -ENODEV;
    }

    uint64_t end = request_mmap_addr + request_mmap_size;
    /* computing the number of pages required for the page tables. */
    unsigned long pts_pages_size = compute_pages(request_mmap_addr, request_mmap_size) * PAGE_SIZE;
    /* Let the address space be filed by the actual regions before doing our mmap.*/
    if (backend_td_mmap(secs->domain, (void*) request_mmap_addr, request_mmap_size,
          PROT_READ | PROT_WRITE | PROT_EXEC, MAP_FIXED_NOREPLACE | MAP_SHARED) != SUCCESS) {
      log_error("Unable to allocate the memory: %s", unix_strerror(errno));
      return -errno;
    }

    uint64_t addr = (uint64_t) secs->domain->mmaps.tail->virtoffset;
    if (IS_PTR_ERR(addr)) {
      int ret = PTR_TO_ERR(addr);
      if (ret == -EPERM) {
          log_error("Permission denied on mapping enclave. "
                    "You may need to set sysctl vm.mmap_min_addr to zero.");
      }

      log_error("Allocation of EPC memory failed: %s", unix_strerror(ret));
      return ret;
    }
    assert(addr == request_mmap_addr);

    /* Allocate shared memory*/
    if (init_shinfo(secs->domain, nb_threads, end) == NULL) {
      log_error("Unable to allocate the init_shinfo");
      return -errno;
    }
    /* Update the end. */
    end += get_shmem_info()->raw_size;

    /* Update the pts_pages to include the shared pages.*/
    shmem_info_t* info = get_shmem_info();
    pts_pages_size += compute_pages(info->raw_start, info->raw_size) * PAGE_SIZE;


    /* now allocate the memory for the domain's page tables. */
    if (backend_td_mmap(secs->domain, (void*) end, pts_pages_size ,
          PROT_READ | PROT_WRITE, MAP_FIXED_NOREPLACE | MAP_SHARED) != SUCCESS) {
      log_error("Unable to mmap the page table memory region.");
      return -errno;
    }
    void* pts = (void*) secs->domain->mmaps.tail->virtoffset;
    memset(pts, 0, pts_pages_size);

    /* add the page tables to the domain.*/
    if (backend_td_register_region(secs->domain,
        (usize) pts, secs->domain->mmaps.tail->size,
        MEM_READ | MEM_WRITE | MEM_SUPER, CONFIDENTIAL) != SUCCESS) {
      log_error("Unable to register the page table mmaps.");
      return -errno;
    }
    /* Initialize the cores and traps.
     * For the moment set default values where we allow everything. */
    secs->domain->traps = NO_TRAPS;
    secs->domain->core_map = (1 << nb_threads) -1;
    secs->domain->perms = DEFAULT_PERM | TYCHE_PERM_CPUID;
    secs->domain->config.page_table_root = secs->domain->mmaps.tail->physoffset;

    /* initialize the pt_mapper */
    init_pt_mapper(secs->domain);

    /* Map the shared memory region now. */
    if (pt_map_region((uint64_t)info->raw_start, info->raw_size,
          PT_PP | PT_RW | PT_NX) != SUCCESS) {
      log_error("Unable to map the shared memory region.");
      return -EINVAL;
    }

    /* Set the traps. */
    if (backend_td_config(
          secs->domain, TYCHE_CONFIG_TRAPS, secs->domain->traps) != SUCCESS) {
      log_error("Unable to set the traps for the domain %d", secs->domain->handle);
      goto failure;
    }
    /* Set the cores. */
    if (backend_td_config(
          secs->domain, TYCHE_CONFIG_CORES, secs->domain->core_map) != SUCCESS) {
      log_error("Unable to set the cores for the domain %d", secs->domain->handle);
      goto failure;
    }
    /* Set the domain permissions. */
    if (backend_td_config(
          secs->domain, TYCHE_CONFIG_PERMISSIONS, secs->domain->perms) != SUCCESS) {
      log_error("Unable to set the permission on domain %d", secs->domain->handle);
      goto failure;
    }

    /* Do the default configuration for mgmt. */
    for (unsigned int p = TYCHE_CONFIG_R16; p < TYCHE_NR_CONFIGS; p++) {
      if (backend_td_config(secs->domain, p, ~((usize) 0)) != SUCCESS) {
        log_error("Unable to set the permission %u", p);
        goto failure;
      }
    }

    secs->attributes.flags |= SGX_FLAGS_INITIALIZED;

    log_debug("Enclave created:");
    log_debug("    base:           0x%016lx", secs->base);
    log_debug("    size:           0x%016lx", secs->size);
    log_debug("    misc_select:    0x%08x",   secs->misc_select);
    log_debug("    attr.flags:     0x%016lx", secs->attributes.flags);
    log_debug("    attr.xfrm:      0x%016lx", secs->attributes.xfrm);
    log_debug("    ssa_frame_size: %d",       secs->ssa_frame_size);

    /* Linux v5.16 introduced support for Intel AMX feature. Any process must opt-in for AMX
     * by issuing an AMX-permission request. More technically, together with AMX, Intel introduced
     * Extended Feature Disable (XFD) which allows Linux to disable certain features from the
     * XSAVE feature set for a particular process. By default, XFD[AMX_TILEDATA] = 1, thus Gramine
     * process has AMX suppressed on startup. This would lead to an unhandled #NM exception on any
     * SGX enclave entry instruction, resulting in fatal SIGILL in Gramine. For more details, see:
     *
     *   - https://elixir.bootlin.com/linux/v5.16/source/arch/x86/kernel/fpu/xstate.c#L934
     *   - https://elixir.bootlin.com/linux/v5.16/source/arch/x86/kernel/traps.c#L1165
     *   - Chapter 3.2.6 in Intel SDM
     *
     * We call arch_prctl() to request AMX permission if the SGX enclave allows/requests it
     * (we examine enclave's SECS.ATTRIBUTES.XFRM). It's enough to do it once: child processes
     * will inherit the permission, but here for simplicity we call it in every child process as
     * well. Some deployment environments run Linux systems earlier than v5.16 but with
     * an AMX-specific patch; this patch doesn't introduce `arch_prctl(ARCH_REQ_XCOMP_PERM)`
     * syscall so an attempt to call it may return EINVAL, EOPNOTSUPP or ENOSYS. In this case,
     * we simply ignore the result of this syscall. */
    if (secs->attributes.xfrm & (1 << AMX_TILEDATA)) {
        ret = DO_SYSCALL(arch_prctl, ARCH_REQ_XCOMP_PERM, AMX_TILEDATA);
        if (ret < 0 && ret != -EINVAL && ret != -EOPNOTSUPP && ret != -ENOSYS) {
            log_error("Requesting AMX permission failed: %s", unix_strerror(ret));
            return ret;
        }
    }

    return 0;
failure:
    return -EINVAL;
}

int add_pages_to_enclave(sgx_arch_secs_t* secs, void* addr, void* user_addr, unsigned long size,
                         enum sgx_page_type type, int prot, bool skip_eextend,
                         const char* comment) {
    __UNUSED(secs); /* Used only under DCAP ifdefs */
    int ret;
    segment_type_t tpe = CONFIDENTIAL;
    memory_access_right_t access = MEM_SUPER;
    uint64_t pt_flags = 0;
    char p[4] = "---";
    if (type == SGX_PAGE_TYPE_REG) {
        if (prot & PROT_READ)
            p[0] = 'R';
        if (prot & PROT_WRITE)
            p[1] = 'W';
        if (prot & PROT_EXEC)
            p[2] = 'X';
    }
    /* Copy the memory content.*/
    if (!user_addr) {
      /* Initialized to 0.*/
      memset(addr, 0, size);
    } else {
      memcpy(addr, user_addr, size);
    }
    /* Compute the access rights. */
    if (prot & PROT_READ) {
      access |= MEM_READ;
      pt_flags |= PT_PP;
    }
    if (prot & PROT_WRITE) {
      access |= MEM_WRITE;
      pt_flags |= PT_RW;
    }
    if (prot & PROT_EXEC) {
      access |= MEM_EXEC;
    } else {
      pt_flags |= PT_NX;
    }
    /* Register the memory region. */
    if (backend_td_register_region(secs->domain, (usize) addr, size, access, tpe) != SUCCESS) {
      log_error("Unable to register %p with size %lx and access %s", addr, size, p);
      return -EINVAL;
    }

    /* map the region in the page tables.*/
    if (pt_map_region(addr, size, pt_flags) != SUCCESS) {
      log_error("Error mapping %p -> %p in page tables", addr, addr + size);
      return -EINVAL;
    }

    // Stop here for now.
    // TODO(aghosn): check in the original sgx implementation if we need to do
    // anything else here. We probably need to protect stack differently
    // and we are still missing the shared memory probably.
    // TODO(aghosn): eventually replace the memory type and all the sgx-related stuff.
    //log_error("Success mapping %p with size %lx and access %s from source %p", addr, size, p, user_addr);
    return 0;
}

int edmm_restrict_pages_perm(uint64_t addr, size_t count, uint64_t prot) {
    assert(addr >= g_pal_enclave.baseaddr);

    size_t i = 0;
    while (i < count) {
        struct sgx_enclave_restrict_permissions params = {
            .offset = addr + i * PAGE_SIZE - g_pal_enclave.baseaddr,
            .length = (count - i) * PAGE_SIZE,
            .permissions = prot,
        };
        int ret = DO_SYSCALL(ioctl, g_isgx_device, SGX_IOC_ENCLAVE_RESTRICT_PERMISSIONS, &params);
        assert(params.count % PAGE_SIZE == 0);
        i += params.count / PAGE_SIZE;
        if (ret < 0) {
            if (ret == -EBUSY || ret == -EAGAIN || ret == -EINTR) {
                continue;
            }
            log_error("SGX_IOC_ENCLAVE_RESTRICT_PERMISSIONS failed (%llu) %s",
                      (unsigned long long)params.result, unix_strerror(ret));
            return ret;
        }
    }

    return 0;
}

int edmm_modify_pages_type(uint64_t addr, size_t count, uint64_t type) {
    assert(addr >= g_pal_enclave.baseaddr);

    int ret;
    size_t i = 0;
    while (i < count) {
        struct sgx_enclave_modify_types params = {
            .offset = addr + i * PAGE_SIZE - g_pal_enclave.baseaddr,
            .length = (count - i) * PAGE_SIZE,
            .page_type = type,
        };
        ret = DO_SYSCALL(ioctl, g_isgx_device, SGX_IOC_ENCLAVE_MODIFY_TYPES, &params);
        assert(params.count % PAGE_SIZE == 0);
        i += params.count / PAGE_SIZE;
        if (ret < 0) {
            if (ret == -EBUSY || ret == -EAGAIN || ret == -EINTR) {
                continue;
            }
            log_error("SGX_IOC_ENCLAVE_MODIFY_TYPES failed: (%llu) %s",
                      (unsigned long long)params.result, unix_strerror(ret));
            return ret;
        }
    }

    if (type == SGX_PAGE_TYPE_TCS) {
        /*
         * In-kernel SGX driver clears PTE permissions of the TCS page upon
         * SGX_IOC_ENCLAVE_MODIFY_TYPES ioctl, and the SGX hardware clears EPCM permissions of the
         * same TCS page upon EMODT instruction (executed as part of the ioctl). Additionally, the
         * SGX driver sets the "max possible permissions" metadata on this TCS page as RW. Note that
         * from this moment on, we mean classic PTE permissions; EPCM permissions always stay
         * cleared (none) for TCS pages.
         *
         * When this page is accessed later, a #PF fault occurs and the Linux kernel tries to map
         * this page into a VMA (i.e., lazy page allocation). At this point, the page-backing VMA
         * must have permissions not exceeding "max possible permissions" saved earlier. E.g., if a
         * VMA was initially mapped with RWX, then the #PF handler for the TCS page will fail, and
         * the page would still be inaccessible due to cleared PTE permissions.
         *
         * Therefore, we must split a new VMA with RW permissions to back this TCS page, by invoking
         * mprotect. Note that creating a VMA with only R permission results in a non-writable TCS
         * page which makes EENTER on that TCS page fail with unrecoverable #PF, and creating a VMA
         * with RWX permissions is explicitly prohibited by the SGX driver.
         */
        ret = DO_SYSCALL(mprotect, addr, count * PAGE_SIZE, PROT_READ | PROT_WRITE);
        if (ret < 0) {
            log_error("Changing protections of TCS pages failed: %s", unix_strerror(ret));
            return ret;
        }
    }

    return 0;
}

int edmm_remove_pages(uint64_t addr, size_t count) {
    assert(addr >= g_pal_enclave.baseaddr);

    size_t i = 0;
    while (i < count) {
        struct sgx_enclave_remove_pages params = {
            .offset = addr + i * PAGE_SIZE - g_pal_enclave.baseaddr,
            .length = (count - i) * PAGE_SIZE,
        };
        int ret = DO_SYSCALL(ioctl, g_isgx_device, SGX_IOC_ENCLAVE_REMOVE_PAGES, &params);
        assert(params.count % PAGE_SIZE == 0);
        i += params.count / PAGE_SIZE;
        if (ret < 0) {
            if (ret == -EBUSY || ret == -EAGAIN || ret == -EINTR) {
                continue;
            }
            return ret;
        }
    }

    return 0;
}

/* must be called after open_sgx_driver() */
int edmm_supported_by_driver(bool* out_supported) {
    struct sgx_enclave_remove_pages params = { .offset = 0, .length = 0 }; /* dummy */
    int ret = DO_SYSCALL(ioctl, g_isgx_device, SGX_IOC_ENCLAVE_REMOVE_PAGES, &params);
    if (ret != -EINVAL && ret != -ENOTTY) {
        /* we expect either -EINVAL (REMOVE_PAGES ioctl exists but fails due to params.length == 0)
         * or -ENOTTY (REMOVE_PAGES ioctl doesn't exist) */
        return ret >= 0 ? -EPERM : ret;
    }
    *out_supported = ret == -EINVAL;
    return 0;
}

int init_enclave(sgx_arch_secs_t* secs, sgx_sigstruct_t* sigstruct, sgx_arch_token_t* token) {
  //TODO(aghosn) this is the commit.
  // we're still missing shared memory regions.
  assert(secs->domain != NULL);
  if (backend_td_commit(secs->domain) != SUCCESS) {
    log_error("Error comitting domain.");
    return -EINVAL;
  }
  return 0;
}
