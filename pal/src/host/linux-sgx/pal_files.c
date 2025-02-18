/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University */

/*
 * This file contains operands to handle streams with URIs that start with "file:" or "dir:".
 */

#include "api.h"
#include "asan.h"
#include "enclave_tf.h"
#include "linux_utils.h"
#include "pal.h"
#include "pal_error.h"
#include "pal_flags_conv.h"
#include "pal_internal.h"
#include "pal_linux.h"
#include "pal_linux_defs.h"
#include "pal_linux_error.h"
#include "pal_sgx.h"
#include "path_utils.h"
#include "stat.h"

/* this macro is used to emulate mmap() via pread() in chunks of 128MB (mmapped files may be many
 * GBs in size, and a pread OCALL could fail with -ENOMEM, so we cap to reasonably small size) */
#define MAX_READ_SIZE (PRESET_PAGESIZE * 1024 * 32)

void fixup_file_handle_after_deserialization(PAL_HANDLE handle) {
    int ret;

    assert(handle->hdr.type == PAL_TYPE_FILE);
    assert(!handle->file.chunk_hashes);
    assert(!handle->file.umem);
    assert(handle->file.realpath);

    if (!handle->file.trusted) {
        /* unknown (if file check policy allows) or encrypted or allowed file, no need to fix */
        return;
    }

    struct trusted_file* tf = get_trusted_or_allowed_file(handle->file.realpath);
    if (!tf || tf->allowed) {
        log_error("cannot find checkpointed trusted file '%s' in manifest", handle->file.realpath);
        die_or_inf_loop();
    }

    tf->size = handle->file.size; /* tf size is required for load_trusted_or_allowed_file() below */

    sgx_chunk_hash_t* chunk_hashes;
    uint64_t file_size;
    void* umem;
    ret = load_trusted_or_allowed_file(tf, handle, /*create=*/false, &chunk_hashes, &file_size,
                                       &umem);
    if (ret < 0) {
        log_error("cannot load checkpointed trusted file '%s'", handle->file.realpath);
        die_or_inf_loop();
    }

    assert(file_size == handle->file.size);
    handle->file.chunk_hashes = chunk_hashes;
    handle->file.umem = umem;
}

static int file_open(PAL_HANDLE* handle, const char* type, const char* uri,
                     enum pal_access pal_access, pal_share_flags_t pal_share,
                     enum pal_create_mode pal_create, pal_stream_options_t pal_options) {
    assert(pal_create != PAL_CREATE_IGNORED);
    int ret;
    int fd = -1;
    PAL_HANDLE hdl = NULL;
    bool do_create = (pal_create == PAL_CREATE_ALWAYS) || (pal_create == PAL_CREATE_TRY);

    int flags = PAL_ACCESS_TO_LINUX_OPEN(pal_access) | PAL_CREATE_TO_LINUX_OPEN(pal_create)
                | PAL_OPTION_TO_LINUX_OPEN(pal_options) | O_CLOEXEC;

    if (strcmp(type, URI_TYPE_FILE))
        return -PAL_ERROR_INVAL;

    /* normalize uri into normpath */
    size_t normpath_size = strlen(uri) + 1;
    char* normpath = malloc(normpath_size);
    if (!normpath)
        return -PAL_ERROR_NOMEM;

    if (!get_norm_path(uri, normpath, &normpath_size)) {
        log_warning("Could not normalize path (%s)", uri);
        free(normpath);
        return -PAL_ERROR_DENIED;
    }

    /* create file PAL handle with path string placed at the end of this handle object */
    hdl = calloc(1, HANDLE_SIZE(file));
    if (!hdl) {
        free(normpath);
        return -PAL_ERROR_NOMEM;
    }

    init_handle_hdr(hdl, PAL_TYPE_FILE);
    hdl->flags |= PAL_HANDLE_FD_READABLE | PAL_HANDLE_FD_WRITABLE;

    hdl->file.realpath = normpath;

    struct trusted_file* tf = NULL;

    if (!(pal_options & PAL_OPTION_PASSTHROUGH)) {
        tf = get_trusted_or_allowed_file(hdl->file.realpath);
        if (!tf) {
            if (get_file_check_policy() != FILE_CHECK_POLICY_ALLOW_ALL_BUT_LOG) {
                log_warning("Disallowing access to file '%s'; file is not trusted or allowed.",
                            hdl->file.realpath);
                ret = -PAL_ERROR_DENIED;
                goto fail;
            }
            log_warning("Allowing access to unknown file '%s' due to file_check_policy settings.",
                        hdl->file.realpath);
        }
    }

    if (tf && !tf->allowed && (do_create
                               || (pal_access == PAL_ACCESS_RDWR)
                               || (pal_access == PAL_ACCESS_WRONLY))) {
        log_error("Disallowing create/write/append to a trusted file '%s'", hdl->file.realpath);
        ret = -PAL_ERROR_DENIED;
        goto fail;
    }

    fd = ocall_open(uri, flags, pal_share);
    if (fd < 0) {
        ret = unix_to_pal_error(fd);
        goto fail;
    }

    struct stat st;
    ret = ocall_fstat(fd, &st);
    if (ret < 0) {
        ret = unix_to_pal_error(ret);
        goto fail;
    }

    hdl->file.fd = fd;
    hdl->file.seekable = !S_ISFIFO(st.st_mode);
    hdl->file.size = st.st_size;

    if (!tf) {
        *handle = hdl;
        return 0;
    }

    /* at this point, we work with a trusted or allowed file */
    tf->size = st.st_size;

    sgx_chunk_hash_t* chunk_hashes;
    uint64_t file_size;
    void* umem;
    ret = load_trusted_or_allowed_file(tf, hdl, do_create, &chunk_hashes, &file_size, &umem);
    if (ret < 0)
        goto fail;

    hdl->file.chunk_hashes = chunk_hashes;
    hdl->file.size = file_size;
    hdl->file.umem = umem;
    hdl->file.trusted = !tf->allowed;

    *handle = hdl;
    return 0;
fail:
    if (fd >= 0)
        ocall_close(fd);
    free(hdl->file.realpath);
    free(hdl);
    return ret;
}

static int64_t file_read(PAL_HANDLE handle, uint64_t offset, uint64_t count, void* buffer) {
    int64_t ret;

    if (!handle->file.trusted) {
        assert(!handle->file.chunk_hashes);
        if (handle->file.seekable) {
            ret = ocall_pread(handle->file.fd, buffer, count, offset);
        } else {
            ret = ocall_read(handle->file.fd, buffer, count);
        }
        return ret < 0 ? unix_to_pal_error(ret) : ret;
    }

    /* case of trusted file: already mmaped in umem, copy from there and verify hash */
    assert(handle->file.chunk_hashes);

    if (offset >= handle->file.size)
        return 0;

    off_t end = MIN(offset + count, handle->file.size);
    off_t aligned_offset = ALIGN_DOWN(offset, TRUSTED_CHUNK_SIZE);
    off_t aligned_end    = ALIGN_UP(end, TRUSTED_CHUNK_SIZE);

    assert(handle->file.size && handle->file.umem);
    ret = copy_and_verify_trusted_file(handle->file.realpath, buffer, handle->file.umem,
                                       aligned_offset, aligned_end, offset, end,
                                       handle->file.chunk_hashes, handle->file.size);
    if (ret < 0)
        return ret;

    return end - offset;
}

static int64_t file_write(PAL_HANDLE handle, uint64_t offset, uint64_t count, const void* buffer) {
    int64_t ret;

    if (!handle->file.trusted) {
        assert(!handle->file.chunk_hashes);
        if (handle->file.seekable) {
            ret = ocall_pwrite(handle->file.fd, buffer, count, offset);
        } else {
            ret = ocall_write(handle->file.fd, buffer, count);
        }
        return ret < 0 ? unix_to_pal_error(ret) : ret;
    }

    /* case of trusted file: disallow writing completely */
    assert(handle->file.chunk_hashes);
    log_warning("Writing to a trusted file (%s) is disallowed!", handle->file.realpath);
    return -PAL_ERROR_DENIED;
}

static void file_destroy(PAL_HANDLE handle) {
    assert(handle->hdr.type == PAL_TYPE_FILE);

    if (handle->file.trusted && handle->file.size) {
        /* case of trusted file: the whole file was mmapped in untrusted memory */
        assert(handle->file.chunk_hashes);
        assert(handle->file.umem);
        ocall_munmap_untrusted(handle->file.umem, handle->file.size);
    }

    int ret = ocall_close(handle->file.fd);
    if (ret < 0) {
        log_error("closing file host fd %d failed: %s", handle->file.fd, unix_strerror(ret));
        /* We cannot do anything about it anyway... */
    }

    free(handle->file.realpath);
    free(handle);
}

static int file_delete(PAL_HANDLE handle, enum pal_delete_mode delete_mode) {
    if (delete_mode != PAL_DELETE_ALL)
        return -PAL_ERROR_INVAL;

    int ret = ocall_delete(handle->file.realpath);
    return ret < 0 ? unix_to_pal_error(ret) : 0;
}

static int file_setlength(PAL_HANDLE handle, uint64_t length) {
    int ret = ocall_ftruncate(handle->file.fd, length);
    if (ret < 0)
        return unix_to_pal_error(ret);

    handle->file.size = length;
    return 0;
}

static int file_flush(PAL_HANDLE handle) {
    int ret = ocall_fsync(handle->file.fd);
    return ret < 0 ? unix_to_pal_error(ret) : 0;
}

static int file_attrquery(const char* type, const char* uri, PAL_STREAM_ATTR* attr) {
    if (strcmp(type, URI_TYPE_FILE) && strcmp(type, URI_TYPE_DIR))
        return -PAL_ERROR_INVAL;

    /* open with O_NONBLOCK to avoid blocking the current thread if it is actually a FIFO pipe */
    int fd = ocall_open(uri, O_NONBLOCK, 0);
    if (fd < 0)
        return unix_to_pal_error(fd);

    struct stat stat_buf;
    int ret = ocall_fstat(fd, &stat_buf);
    if (ret < 0) {
        ret = unix_to_pal_error(ret);
        goto out;
    }

    file_attrcopy(attr, &stat_buf);
    ret = 0;
out:
    ocall_close(fd);
    return ret;
}

static int file_attrquerybyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    struct stat stat_buf;

    int ret = ocall_fstat(handle->file.fd, &stat_buf);
    if (ret < 0)
        return unix_to_pal_error(ret);

    file_attrcopy(attr, &stat_buf);
    return 0;
}

static int file_attrsetbyhdl(PAL_HANDLE handle, PAL_STREAM_ATTR* attr) {
    int ret = ocall_fchmod(handle->file.fd, attr->share_flags);
    return ret < 0 ? unix_to_pal_error(ret) : 0;
}

static int file_rename(PAL_HANDLE handle, const char* type, const char* uri) {
    if (strcmp(type, URI_TYPE_FILE))
        return -PAL_ERROR_INVAL;

    char* tmp = strdup(uri);
    if (!tmp)
        return -PAL_ERROR_NOMEM;

    int ret = ocall_rename(handle->file.realpath, uri);
    if (ret < 0) {
        free(tmp);
        return unix_to_pal_error(ret);
    }

    free(handle->file.realpath);
    handle->file.realpath = tmp;
    return 0;
}

static int dir_open(PAL_HANDLE* handle, const char* type, const char* uri, enum pal_access access,
                    pal_share_flags_t share, enum pal_create_mode create,
                    pal_stream_options_t options) {
    __UNUSED(access);

    if (strcmp(type, URI_TYPE_DIR))
        return -PAL_ERROR_INVAL;

    if (create == PAL_CREATE_TRY || create == PAL_CREATE_ALWAYS) {
        int ret = ocall_mkdir(uri, share);

        if (ret < 0) {
            if (ret == -EEXIST && create == PAL_CREATE_ALWAYS)
                return -PAL_ERROR_STREAMEXIST;
            if (ret != -EEXIST)
                return unix_to_pal_error(ret);
            assert(ret == -EEXIST && create == PAL_CREATE_TRY);
        }
    }

    int fd = ocall_open(uri, O_DIRECTORY | O_CLOEXEC | PAL_OPTION_TO_LINUX_OPEN(options), 0);
    if (fd < 0)
        return unix_to_pal_error(fd);

    PAL_HANDLE hdl = calloc(1, HANDLE_SIZE(dir));
    if (!hdl) {
        ocall_close(fd);
        return -PAL_ERROR_NOMEM;
    }

    init_handle_hdr(hdl, PAL_TYPE_DIR);

    hdl->flags |= PAL_HANDLE_FD_READABLE;
    hdl->dir.fd = fd;

    char* path = strdup(uri);
    if (!path) {
        ocall_close(fd);
        free(hdl);
        return -PAL_ERROR_NOMEM;
    }

    hdl->dir.realpath    = path;
    hdl->dir.buf         = NULL;
    hdl->dir.ptr         = NULL;
    hdl->dir.end         = NULL;
    hdl->dir.endofstream = false;
    *handle              = hdl;
    return 0;
}

#define DIRBUF_SIZE 1024

static int64_t dir_read(PAL_HANDLE handle, uint64_t offset, size_t count, void* _buf) {
    size_t bytes_written = 0;
    char* buf            = (char*)_buf;

    if (offset) {
        return -PAL_ERROR_INVAL;
    }

    if (handle->dir.endofstream) {
        return 0;
    }

    while (1) {
        while ((char*)handle->dir.ptr < (char*)handle->dir.end) {
            struct linux_dirent64* dirent = (struct linux_dirent64*)handle->dir.ptr;

            if (is_dot_or_dotdot(dirent->d_name)) {
                goto skip;
            }

            bool is_dir = dirent->d_type == DT_DIR;
            size_t len  = strlen(dirent->d_name);

            if (len + 1 + (is_dir ? 1 : 0) > count) {
                goto out;
            }

            memcpy(buf, dirent->d_name, len);
            if (is_dir) {
                buf[len++] = '/';
            }
            buf[len++] = '\0';

            buf += len;
            bytes_written += len;
            count -= len;
        skip:
            handle->dir.ptr = (char*)handle->dir.ptr + dirent->d_reclen;
        }

        if (!count) {
            /* No space left, returning */
            goto out;
        }

        if (!handle->dir.buf) {
            handle->dir.buf = malloc(DIRBUF_SIZE);
            if (!handle->dir.buf) {
                return -PAL_ERROR_NOMEM;
            }
        }

        int size = ocall_getdents(handle->dir.fd, handle->dir.buf, DIRBUF_SIZE);
        if (size < 0) {
            /*
             * If something was written just return that and pretend no error
             * was seen - it will be caught next time.
             */
            if (bytes_written) {
                return bytes_written;
            }
            return unix_to_pal_error(size);
        }

        if (!size) {
            handle->dir.endofstream = true;
            goto out;
        }

        handle->dir.ptr = handle->dir.buf;
        handle->dir.end = (char*)handle->dir.buf + size;
    }

out:
    return (int64_t)bytes_written;
}

static void dir_destroy(PAL_HANDLE handle) {
    assert(handle->hdr.type == PAL_TYPE_DIR);

    int ret = ocall_close(handle->dir.fd);
    if (ret < 0) {
        log_error("closing dir host fd %d failed: %s", handle->dir.fd, unix_strerror(ret));
        /* We cannot do anything about it anyway... */
    }

    free(handle->dir.buf);
    free(handle->dir.realpath);
    free(handle);
}

static int dir_delete(PAL_HANDLE handle, enum pal_delete_mode delete_mode) {
    if (delete_mode != PAL_DELETE_ALL)
        return -PAL_ERROR_INVAL;

    int ret = ocall_delete(handle->dir.realpath);
    return ret < 0 ? unix_to_pal_error(ret) : 0;
}

static int dir_rename(PAL_HANDLE handle, const char* type, const char* uri) {
    if (strcmp(type, URI_TYPE_DIR))
        return -PAL_ERROR_INVAL;

    char* tmp = strdup(uri);
    if (!tmp)
        return -PAL_ERROR_NOMEM;

    int ret = ocall_rename(handle->dir.realpath, uri);
    if (ret < 0) {
        free(tmp);
        return unix_to_pal_error(ret);
    }

    free(handle->dir.realpath);
    handle->dir.realpath = tmp;
    return 0;
}

struct handle_ops g_file_ops = {
    .open           = &file_open,
    .read           = &file_read,
    .write          = &file_write,
    .destroy        = &file_destroy,
    .delete         = &file_delete,
    .setlength      = &file_setlength,
    .flush          = &file_flush,
    .attrquery      = &file_attrquery,
    .attrquerybyhdl = &file_attrquerybyhdl,
    .attrsetbyhdl   = &file_attrsetbyhdl,
    .rename         = &file_rename,
};

struct handle_ops g_dir_ops = {
    .open           = &dir_open,
    .read           = &dir_read,
    .destroy        = &dir_destroy,
    .delete         = &dir_delete,
    .attrquery      = &file_attrquery,
    .attrquerybyhdl = &file_attrquerybyhdl,
    .attrsetbyhdl   = &file_attrsetbyhdl,
    .rename         = &dir_rename,
};
