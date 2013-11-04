/*
 * writer.h
 *
 *  Created on: Aug 8, 2012
 *      Original Author: Yotam Rubin
 *      Maintainer:		 Yitzik Casapu, Infinidat
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

#ifndef WRITER_H_
#define WRITER_H_

#include <sys/uio.h>
#include <pthread.h>
#include "../bool.h"
#include "trace_dumper.h"


int write_single_record(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, const struct trace_record *rec);

/* Write to the output file using a mechanism selected according to conf->low_latency_write, and optionally dump traces to the parser. */
int trace_dumper_write(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, const struct iovec *iov, int iovcnt);

/* A wrapper for trace_dumper_write which syncs the written data to the disk after the write. */
int trace_dumper_write_to_record_file(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file);

/* If the existing size of the IO vector is insufficient to hold size_t records, increase it by at least 50% */
struct iovec *increase_iov_if_necessary(struct trace_record_file *record_file, size_t required_size);

/* Lower level trace writing functions that use specific mechanisms */
int trace_dumper_write_via_file_io(const struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, const struct iovec *iov, int iovcnt);

void trace_dumper_update_written_record_count(struct trace_record_file *record_file);
bool_t trace_dumper_record_file_state_is_ok(const struct trace_record_file *record_file);

/* Get the actual position in the file of the next record to be written, taking the internal buffer into account */
trace_record_counter_t trace_dumper_get_effective_record_file_pos(const struct trace_record_file *record_file);

/* Async writing */
struct aiocb *trace_dumper_get_vacant_aiocb(struct trace_record_file *record_file, trace_ts_t timeout);

/*  Try to enqueue records for async writing and return the number of records enqueued, or -1 if that's not possible */
int trace_dumper_write_async_if_possible(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, const struct trace_record *records, size_t n_records);

bool_t trace_dumper_record_file_has_pending_async_io(const struct trace_record_file *record_file);

int trace_dumper_wait_record_file_async_io_completion(struct trace_record_file *record_file, trace_ts_t timeout);

static inline bool_t trace_dumper_async_timed_out(void)
{
    const int e = errno;
    return ((EAGAIN == e) || (EINTR == e));
}

static inline size_t trace_dumper_async_num_recs_pending(const struct trace_record_file *record_file)
{
    const struct aiocb *const cb = record_file->async_writes;
    return (cb->aio_fildes >= 0) ? cb->aio_nbytes / TRACE_RECORD_SIZE : 0;
}

static inline size_t trace_dumper_async_num_recs_pending_active_file(const struct trace_record_file *record_file)
{
    const struct aiocb *const cb = record_file->async_writes;
    return (cb->aio_fildes == record_file->fd) ? trace_dumper_async_num_recs_pending(record_file) : 0;
}

size_t trace_dumper_net_num_records_pending(const struct trace_record_file *record_file);

void trace_dumper_async_clear_iocb(struct aiocb *cb);

#endif /* WRITER_H_ */
