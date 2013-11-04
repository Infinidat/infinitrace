/*
 * internal_buffer.h
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


#ifndef INTERNAL_BUFFER_H_
#define INTERNAL_BUFFER_H_

#include <sys/types.h>
#include <sys/uio.h>

#include "../trace_defs.h"

struct trace_internal_buf_index {
    unsigned t;     /* Tentative, not yet to be considered committed */
    unsigned c;     /* Committed */
};

struct trace_internal_buf {
    struct trace_internal_buf_index write_idx;
    struct trace_internal_buf_index read_idx;
    unsigned n_recs;
    struct trace_internal_buf_index n_slack_recs;    /* number of unused records at buffer end */
    struct trace_record records[0] __attribute__((aligned(TRACE_RECORD_SIZE))) ;
};

/* TODO: For multithreading separate tentative allocations from permanent allocations */

struct trace_internal_buf *internal_buf_alloc(size_t size);
int internal_buf_free(struct trace_internal_buf *buf);
int internal_buf_free_and_invalidate(struct trace_internal_buf **p_buf);
struct trace_record *internal_buf_write_recs(struct trace_internal_buf *buf, const struct trace_record *recs, size_t n_recs);

/* Compress bytes given in iov. Return number of compressed bytes, or -1 on error */
ssize_t internal_buf_write_compressed(struct trace_internal_buf *buf, const struct iovec *iov, int iovcnt);

unsigned internal_buf_num_recs_pending(const struct trace_internal_buf *buf);

/* Prepare a single iovec with the next segment of contiguous data pending read from the buffer */
bool_t internal_buf_contiguous_pending_read_as_iov(struct trace_internal_buf *buf, struct iovec *iov);

/* Prepare an iovec with up to 2 entries with all the data pending read from the buffer */
void internal_buf_create_iov_for_pending_reads(struct trace_internal_buf *buf, struct iovec iov[2], int *iovcnt);

/* Commit (copy tentative counters to committed) and rollback (copy committed to tentative) reads and writes */
void internal_buf_commit_write(struct trace_internal_buf *buf);
void internal_buf_commit_read(struct trace_internal_buf *buf);
void internal_buf_rollback_write(struct trace_internal_buf *buf);
void internal_buf_rollback_read(struct trace_internal_buf *buf);

static inline size_t internal_buf_bytes_to_recs(size_t n_bytes)
{
    return (n_bytes + TRACE_RECORD_SIZE - 1) / TRACE_RECORD_SIZE;
}

#define INTERNAL_BUF_INVALID_INDEX ((unsigned) -1)

#endif /* INTERNAL_BUFFER_H_ */
