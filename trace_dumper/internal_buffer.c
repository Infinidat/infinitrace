/*
 * internal_buffer.c
 * Routines for accessing trace dumper's internal data buffer
 *
 *  Created on: Oct 22, 2013
 *  Author:     Yitzik Casapu, Infinidat
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stddef.h>     /* for offsetof */

#include "../snappy/snappy.h"
#include "../trace_macros.h"
#include "../trace_mmap_util.h"
#include "../trace_str_util.h"
#include "../min_max.h"
#include "../trace_macros.h"
#include "../trace_user.h"

#include "sgio_util.h"
#include "internal_buffer.h"

enum internal_buffer_constants {
    BUF_HEADER_SIZE =  offsetof(struct trace_internal_buf, records),
};

struct trace_internal_buf *internal_buf_alloc(size_t size)
{
    const size_t alloc_size = trace_round_size_up_to_page_size(size);
    struct trace_internal_buf *const buf = (struct trace_internal_buf *) trace_mmap_private_anon_mem(alloc_size);
    if (MAP_FAILED == buf) {
        return NULL;
    }

    TRACE_COMPILE_TIME_ASSERT_IS_ZERO(BUF_HEADER_SIZE % TRACE_RECORD_SIZE);
    memset(buf, 0, BUF_HEADER_SIZE);
    buf->n_recs = (alloc_size - BUF_HEADER_SIZE) / TRACE_RECORD_SIZE;
    return buf;
}

int internal_buf_free(struct trace_internal_buf *buf)
{
    if (NULL != buf)
    {
        const size_t len = TRACE_RECORD_SIZE * buf->n_recs + BUF_HEADER_SIZE;
        TRACE_ASSERT(trace_round_size_up_to_page_size(len) == len);
        if (munmap(buf, len) != 0) {
            return -1;
        }
    }

    return 0;
}

int internal_buf_free_and_invalidate(struct trace_internal_buf **p_buf)
{
    if (NULL == p_buf) {
        errno = EFAULT;
        return -1;
    }

    if (internal_buf_free(*p_buf) != 0) {
        return -1;
    }

    *p_buf = NULL;
    return 0;
}

unsigned internal_buf_alloc_space(struct trace_internal_buf *buf, size_t n_recs)
{
    unsigned ret = INTERNAL_BUF_INVALID_INDEX;
    if (buf->write_idx.t >= buf->read_idx.c) {
        if (INTERNAL_BUF_INVALID_INDEX == buf->write_idx.t) {
            errno = ENOMEM;
        }

        if (buf->n_recs >= buf->write_idx.t + n_recs) {
            ret = buf->write_idx.t;
            buf->write_idx.t += n_recs;
        }
        else if (buf->read_idx.c >= n_recs) {  /* Try to allocate space at the beginning */
            buf->n_slack_recs.t = buf->n_recs - buf->write_idx.t;
            buf->write_idx.t = n_recs;
            ret = 0;
        }
        else {
            errno = ENOMEM;
        }
    }
    else {  /* Write has wrapped around, read hasn't yet */
        if (buf->read_idx.c >= buf->write_idx.t + n_recs) {
            ret = buf->write_idx.t;
            buf->write_idx.t += n_recs;
        }
        else {
            errno = ENOMEM;
        }
    }

    if ((buf->write_idx.t == buf->read_idx.c) && (n_recs > 0)) {
        buf->write_idx.t = INTERNAL_BUF_INVALID_INDEX;
    }

    return ret;
}

struct trace_record *internal_buf_write_recs(struct trace_internal_buf *buf, const struct trace_record *recs, size_t n_recs)
{
    unsigned start_idx = internal_buf_alloc_space(buf, n_recs);
    if (INTERNAL_BUF_INVALID_INDEX == start_idx) {
        return NULL;
    }

    struct trace_record *const p = buf->records + start_idx;
    memcpy(p, recs, TRACE_RECORD_SIZE * n_recs);
    return p;
}

static ssize_t compress_iov_to_buffer(struct trace_record *target, const struct iovec *iov, int iovcnt)
{
    if (NULL == iov) {
        errno = EFAULT;
        return -1;
    }

    if (iovcnt < 1) {
        return 0;
    }

    char *src_buf = iov[0].iov_base;
    size_t input_len = iov[0].iov_len;
    size_t compressed_length = 0;
    struct snappy_env env;
    int rc = snappy_init_env(&env);
    if (rc < 0) {
        goto finish;
    }

    if (iovcnt > 1) {
        /* TODO: Snappy should be able to accept an input IOV directly. Since this support is currently broken we use a workaround instead. */
        input_len = total_iovec_len(iov, iovcnt);
        src_buf = malloc(input_len);
        if ((NULL == src_buf) || (copy_iov_to_buffer(src_buf, iov, iovcnt) != (ssize_t) input_len)) {
            rc = -errno;
            goto finish;
        }

    }

    if (input_len > 0) {
        /* Don't bother compressing trailing padding chars. Those will be re-inserted by the reader. */
        input_len -= trace_r_count_chr_occurrences(src_buf + 1, input_len - 1, TRACE_UNUSED_SPACE_FILL_VALUE);
        rc = snappy_compress(&env, src_buf, input_len, (char *)target, &compressed_length);
    }

finish:
    snappy_free_env(&env);

    if (src_buf != iov[0].iov_base) {
        free(src_buf);
    }

    if (0 != rc) {
        errno = -rc;
        ERR("Buffer compression failed with err", errno, strerror(errno));
        return (ssize_t) -1;
    }

    TRACE_ASSERT(((ssize_t) compressed_length > 0) || (0 == input_len));
    return (ssize_t) compressed_length;
}

static unsigned effective_capacity_t(const struct trace_internal_buf *buf)
{
    TRACE_ASSERT(buf->n_recs > buf->n_slack_recs.t);
    return buf->n_recs - buf->n_slack_recs.t;
}

static unsigned effective_capacity_c(const struct trace_internal_buf *buf)
{
    TRACE_ASSERT(buf->n_recs > buf->n_slack_recs.c);
    return buf->n_recs - buf->n_slack_recs.c;
}

static void compactify_buffer(struct trace_internal_buf *buf, unsigned start_idx, unsigned actually_used)
{
    TRACE_ASSERT(buf->write_idx.t >= start_idx + actually_used);
    if ((0 == start_idx) && (buf->n_slack_recs.t >= actually_used)) {
        DEBUG("Copying", actually_used, "records into slack space", buf->write_idx.t, buf->n_slack_recs.t);
        memcpy(buf->records + effective_capacity_t(buf), buf->records, TRACE_RECORD_SIZE * actually_used);
        buf->n_slack_recs.t -= actually_used;
        buf->write_idx.t = effective_capacity_t(buf);
    }
    else {
        buf->write_idx.t = start_idx + actually_used;
    }
}

static void fill_compression_remainder_with_pattern(struct trace_internal_buf *buf, size_t compressed_len)
{
    char *const end_p = (char *)(buf->records + buf->write_idx.t);
    const size_t fill_len = TRACE_RECORD_SIZE * internal_buf_bytes_to_recs(compressed_len) - compressed_len;
    TRACE_ASSERT(fill_len < TRACE_RECORD_SIZE);
    memset(end_p - fill_len, 0x69, fill_len);
}

ssize_t internal_buf_write_compressed(struct trace_internal_buf *buf, const struct iovec *iov, int iovcnt)
{
    const size_t max_size = snappy_max_compressed_length(total_iovec_len(iov, iovcnt));
    const size_t max_recs = internal_buf_bytes_to_recs(max_size);
    const unsigned start_idx = internal_buf_alloc_space(buf, max_recs);
    if (INTERNAL_BUF_INVALID_INDEX == start_idx) {
        return -1;
    }

    const ssize_t compressed_len = compress_iov_to_buffer(buf->records + start_idx, iov, iovcnt);
    if (compressed_len < 0) {
        compactify_buffer(buf, start_idx, 0);
        return -1;
    }

    compactify_buffer(buf, start_idx, internal_buf_bytes_to_recs(compressed_len));
    fill_compression_remainder_with_pattern(buf, compressed_len);

    return compressed_len;
}

static unsigned internal_buf_recs_ahead_of_read_c(struct trace_internal_buf *buf, size_t n_recs)
{
    const unsigned read_till_slack = effective_capacity_c(buf) - buf->read_idx.c;
    if (n_recs < read_till_slack) {
        return buf->read_idx.c + n_recs;
    }

    return n_recs - read_till_slack;
}

unsigned internal_buf_num_recs_pending(const struct trace_internal_buf *buf)
{
    if (!buf) {
        return 0;
    }

    if (buf->write_idx.c >= buf->read_idx.c) {
        if (INTERNAL_BUF_INVALID_INDEX == buf->write_idx.c) {
            return effective_capacity_c(buf);
        }

        return buf->write_idx.c - buf->read_idx.c;
    }

    return effective_capacity_c(buf) + buf->write_idx.c - buf->read_idx.c;
}

void internal_buf_create_iov_for_pending_writes(struct trace_internal_buf *buf, struct iovec iov[2], int *iovcnt)
{
    const unsigned num_recs_pending = internal_buf_num_recs_pending(buf);
    if (0 == num_recs_pending) {
        *iovcnt = 0;
    }

    iov[0].iov_base = buf->records + buf->read_idx.c;
    if (buf->read_idx.c + num_recs_pending <= effective_capacity_c(buf)) {
        *iovcnt = 1;
        iov[0].iov_len = TRACE_RECORD_SIZE * num_recs_pending;
    }
    else {
        *iovcnt = 2;
        TRACE_ASSERT(effective_capacity_c(buf) > buf->read_idx.c);
        iov[0].iov_len = TRACE_RECORD_SIZE * (effective_capacity_c(buf) - buf->read_idx.c);
        iov[1].iov_base = buf->records;
        iov[1].iov_len = TRACE_RECORD_SIZE * (num_recs_pending - iov[0].iov_len / TRACE_RECORD_SIZE);
    }

    if (INTERNAL_BUF_INVALID_INDEX == buf->write_idx.t) {
        buf->write_idx.t = buf->read_idx.t;
    }
    buf->read_idx.t = internal_buf_recs_ahead_of_read_c(buf, num_recs_pending);
}

#define ROLLBACK_COUNTER(ctr) buf-> ctr .t = buf-> ctr .c
#define COMMIT_COUNTER(ctr)   buf-> ctr .c = buf-> ctr .t
#define CTR_WRAPPED_AROUND(ctr) (buf-> ctr ##_idx .t < buf-> ctr ##_idx .c)

void internal_buf_commit_write(struct trace_internal_buf *buf)
{
    if (CTR_WRAPPED_AROUND(write)) {
        COMMIT_COUNTER(n_slack_recs);
    }
    COMMIT_COUNTER(write_idx);
}

void internal_buf_commit_read(struct trace_internal_buf *buf)
{
    if (CTR_WRAPPED_AROUND(read)) {
        COMMIT_COUNTER(n_slack_recs);
    }
    COMMIT_COUNTER(read_idx);
}

void internal_buf_rollback_write(struct trace_internal_buf *buf)
{
    if (CTR_WRAPPED_AROUND(write)) {
        ROLLBACK_COUNTER(n_slack_recs);
    }
    ROLLBACK_COUNTER(write_idx);
}

void internal_buf_rollback_read(struct trace_internal_buf *buf)
{
    if (CTR_WRAPPED_AROUND(read)) {
        ROLLBACK_COUNTER(n_slack_recs);
    }
    ROLLBACK_COUNTER(read_idx);
}
