/*
 * writer.c
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

#include "../platform.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

#include "../trace_user.h"
#include "../min_max.h"
#include "../trace_clock.h"
#include "filesystem.h"
#include "events.h"
#include "sgio_util.h"
#include "internal_buffer.h"
#include "mm_writer.h"
#include "writer.h"
#include "open_close.h"


struct iovec *increase_iov_if_necessary(struct trace_record_file *record_file, size_t required_size)
{
	if (required_size > record_file->iov_allocated_len) {
		record_file->iov_allocated_len = MAX(required_size, record_file->iov_allocated_len + record_file->iov_allocated_len/2);
		record_file->iov = (struct iovec *)realloc(record_file->iov, sizeof(struct iovec) * record_file->iov_allocated_len);
	}
	return record_file->iov;
}


int write_single_record(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, const struct trace_record *rec)
{
	const size_t len = sizeof(*rec);
	const struct iovec iov = {
			(void *)rec,
			len
	};

	int rc = trace_dumper_write(conf, record_file, &iov, 1);
    if ((int)len != rc) {
    	if (rc >= 0) { /* Partial write */
    		errno = ETIMEDOUT;
    	}
        return -1;
    }
    return 0;
}


int trace_dumper_write(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, const struct iovec *iov, int iovcnt)
{
	int ret = -1;
	if (conf->low_latency_write) {
		ret = trace_dumper_write_via_mmapping(conf, record_file, iov, iovcnt);
		if ((ret < 0) && (EAGAIN == errno)) {
			const size_t len = total_iovec_len(iov, iovcnt);
			record_file->records_discarded += len / TRACE_RECORD_SIZE;
			const struct trace_output_mmap_info const *info = record_file->mapping_info;
			syslog(LOG_USER|LOG_WARNING,
					"Trace dumper has had to discard %lu records due to insufficient buffer space (%lu-%lu=%lu>%lu) while writing to the file %s",
					len / TRACE_RECORD_SIZE,
					info->records_written, info->records_committed, num_records_pending(record_file->mapping_info),
					conf->max_records_pending_write_via_mmap,
					record_file->filename);
		}
		else {
            trace_dumper_update_written_record_count(record_file);
        }
	}
	else {
		ret = trace_dumper_write_via_file_io(conf, record_file, iov, iovcnt);
	}

	return ret;
}


int trace_dumper_write_via_file_io(const struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, const struct iovec *iov, int iovcnt)
{
	int expected_bytes = total_iovec_len(iov, iovcnt);
    int rc = 0;
    unsigned retries_due_to_full_fs = 0;
    unsigned retries_due_to_partial_write = 0;
    const useconds_t retry_interval = TRACE_SECOND / 60;
    const useconds_t partial_write_retry_interval = 10000;

    if (record_file->fd < 0) {
    	errno = EBADF;
    	expected_bytes = -1;
    }
    else if (expected_bytes > 0)
    {
        while (TRUE) {
            if (iovcnt >= sysconf(_SC_IOV_MAX)) {
                rc = trace_dumper_writev(record_file->fd, iov, iovcnt);
            } else {
                rc = writev(record_file->fd, iov, iovcnt);
            }

            if (rc < 0) {
            	if (errno == ENOSPC) {
					if (0 == retries_due_to_full_fs)
					{
						syslog(LOG_USER|LOG_WARNING, "Writing traces to %s paused due to a full filesystem", record_file->filename);
					}

					++retries_due_to_full_fs;
					if (0!= handle_full_filesystem(conf, iov, iovcnt)) {
						usleep(retry_interval);
					}
					continue;
            	}
            	else if (errno == EINTR) { /* Received a non-fatal signal, probably USR1 or USR2 */
            		continue;
            	}
            	else
            	{
            		syslog(LOG_USER|LOG_ERR, "Had unexpected error %s while writing to %s", strerror(errno), record_file->filename);
            		expected_bytes = -1;
            		break;
            	}
            }
            else if (rc != expected_bytes) {
            	int err = errno;

            	ERR("Only wrote", rc, "of", expected_bytes, "bytes, and got error", err, ". rewinding by the number of bytes written");
            	off64_t eof_pos = lseek64(record_file->fd, (off64_t)-rc, SEEK_CUR);
            	if (TEMP_FAILURE_RETRY(ftruncate64(record_file->fd, eof_pos)) < 0) {
            		return -1;
            	}

            	if (0 == retries_due_to_partial_write % 500) {
            		syslog(LOG_USER|LOG_WARNING, "Writing traces to %s had to be rolled back since only %d of %d bytes were written. retried %u times so far.",
            				record_file->filename, rc, expected_bytes, retries_due_to_partial_write);
            	}
            	++retries_due_to_partial_write;
            	usleep(partial_write_retry_interval);
            	continue;
            }

            if (retries_due_to_full_fs > 0) {
            	syslog(LOG_USER|LOG_NOTICE,
            		  "Writing traces to %s resumed after a pause due a full file-system after %u retries every %.2f seconds",
            		  record_file->filename, retries_due_to_full_fs, retry_interval/1E6);
            	retries_due_to_full_fs = 0;
            }

            if (retries_due_to_partial_write > 0) {
                syslog(LOG_USER|LOG_NOTICE,
				  "Writing traces to %s resumed after a pause due to to a partial write after %u retries every %.1f ms",
				  record_file->filename, retries_due_to_partial_write, partial_write_retry_interval/1000.0);
                retries_due_to_partial_write = 0;
            }

            record_file->records_written += expected_bytes / sizeof(struct trace_record);
            break;
        }
    }

    return expected_bytes;
}

int trace_dumper_write_to_record_file(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file)
{
	int num_warn_bytes = total_iovec_len(record_file->iov, record_file->iov_count);
	if (num_warn_bytes > 0) {
		if (is_closed(record_file)) {
				errno = EBADF;
				return -1;
		}

		if (trace_dumper_write(conf, record_file, record_file->iov, record_file->iov_count) != num_warn_bytes) {
			syslog(LOG_USER|LOG_ERR,
					"Trace dumper encountered the following error while writing %d bytes to the file %s: %s",
					num_warn_bytes, record_file->filename, strerror(errno));
			return -1;
		}
    }

	record_file->iov_count = 0;
	return num_warn_bytes;
}


void trace_dumper_update_written_record_count(struct trace_record_file *record_file)
{
    trace_mm_writer_update_written_record_count(record_file);
}

trace_record_counter_t trace_dumper_get_effective_record_file_pos(const struct trace_record_file *record_file)
{
    /* TODO: This function can be used to eliminate the need for trace_dumper_update_written_record_count.
     * NOTE: In a multithreaded implementation there can be a race condition between the update of the records written by the writer thread and the
     * obtaining of the number of records pending here, causing some records to be counted twice. */
    return  record_file->records_written +
            trace_dumper_net_num_records_pending(record_file) +
            trace_dumper_async_num_recs_pending_active_file(record_file);
}

bool_t trace_dumper_record_file_state_is_ok(const struct trace_record_file *record_file)
{
	if (trace_is_record_file_using_mm(record_file)) {
		return (0 == record_file->mapping_info->lasterr);
	}

	return TRUE;
}

bool_t trace_dumper_record_file_has_pending_async_io(const struct trace_record_file *record_file)
{
    return record_file->async_writes[0].aio_fildes >= 0;
}

size_t trace_dumper_net_num_records_pending(const struct trace_record_file *record_file)
{
    const size_t internal_buf_pending = internal_buf_num_recs_pending(record_file->internal_buf);
    const size_t async_write_pending  = trace_dumper_async_num_recs_pending(record_file);
    TRACE_ASSERT(internal_buf_pending >= async_write_pending);
    return internal_buf_pending - async_write_pending;
}

struct aiocb *trace_dumper_get_vacant_aiocb(struct trace_record_file *record_file, trace_ts_t timeout)
{
    if (!trace_dumper_record_file_has_pending_async_io(record_file)) {
        return record_file->async_writes;
    }

    const struct aiocb *const cblist[] = { record_file->async_writes };
    struct timespec ts_timeout;
    struct timespec *p_timeout = NULL;

    if ((TRACE_FOREVER != timeout)) {
        p_timeout = &ts_timeout;
        trace_init_timespec(p_timeout, timeout);
    }

    const int rc = aio_suspend(cblist, ARRAY_LENGTH(cblist), p_timeout);
    if (rc < 0) {
        switch (errno) {
        case EINTR:
            DEBUG("Wait for a vacant aiocb has been interrupted by a signal");
            /* no break - handle same as EAGAIN */

        case EAGAIN:
            break;

        default:
            ERR("Unexpected error while waiting for async IO", errno, strerror(errno));
            break;
        }

        return NULL;
    }

    const trace_record_counter_t effective_pos = trace_dumper_get_effective_record_file_pos(record_file);
    const trace_async_write_completion completion = record_file->async_completion_routine;
    const bool_t completion_failed = completion && (completion(record_file, record_file->async_writes) < 0);
    off64_t offset_increment = record_file->async_writes[0].aio_nbytes;
    if (completion_failed) {
        TRACE_ASSERT(0 != errno);
        ERR("Async write completion routine failed with error", errno, strerror(errno));
        offset_increment = 0;
    }

    const off64_t new_offset = lseek64(record_file->async_writes[0].aio_fildes, 0, SEEK_END);
    TRACE_ASSERT(record_file->async_writes[0].aio_offset + offset_increment == new_offset);
    if (record_file->async_writes[0].aio_fildes == record_file->fd) {
        TRACE_ASSERT(((size_t) new_offset == record_file->records_written * TRACE_RECORD_SIZE));
    }
    else if (close_async_write_fd(record_file) < 0) {
        record_file->async_writes->aio_nbytes = 0;
        return NULL;
    }

    trace_dumper_async_clear_iocb(record_file->async_writes);

    /* Make sure that no records were lost or duplicated in the process */
    TRACE_ASSERT(trace_dumper_get_effective_record_file_pos(record_file) == effective_pos);

    return completion_failed ? NULL : record_file->async_writes;
}

int trace_dumper_wait_record_file_async_io_completion(struct trace_record_file *record_file, trace_ts_t timeout)
{
    if (record_file->async_writes[0].aio_fildes != record_file->fd) {
        return 0;       /* Pending I/O is for another file, presumably the one we are about to close */
    }

    if (NULL == trace_dumper_get_vacant_aiocb(record_file, timeout)) {
        return -1;
    }

    return 0;
}

int trace_dumper_write_async_if_possible(
        struct trace_dumper_configuration_s *conf __attribute__((unused)), struct trace_record_file *record_file, const struct trace_record *records, size_t n_records)
{
    if (is_closed(record_file)) {
        errno = EBADF;
        return -1;
    }

    struct aiocb *const cb = trace_dumper_get_vacant_aiocb(record_file, 0);
    if (NULL == cb) {
        return -1;
    }

    TRACE_ASSERT(-1 == cb->aio_fildes);
    memset(cb, 0, sizeof(*cb));
    cb->aio_buf = (volatile void *) records;
    cb->aio_fildes = record_file->fd;
    cb->aio_nbytes = TRACE_RECORD_SIZE * n_records;
    cb->aio_offset = TRACE_RECORD_SIZE * record_file->records_written;
    return aio_write(cb);
}

void trace_dumper_async_clear_iocb(struct aiocb *cb)
{
    memset(cb, 0, sizeof(*cb));
    cb->aio_fildes = -1;
}
