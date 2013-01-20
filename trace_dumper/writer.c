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
#include "writer.h"
#include "open_close.h"

size_t total_iovec_len(const struct iovec *iov, int iovcnt)
{
	size_t total = 0;
    int i;
    for (i = 0; i < iovcnt; i++) {
        total += iov[i].iov_len;
    }

    return total;
}

struct iovec *increase_iov_if_necessary(struct trace_record_file *record_file, size_t required_size)
{
	if (required_size > record_file->iov_allocated_len) {
		record_file->iov_allocated_len = MAX(required_size, record_file->iov_allocated_len + record_file->iov_allocated_len/2);
		record_file->iov = (struct iovec *)realloc(record_file->iov, sizeof(struct iovec) * record_file->iov_allocated_len);
	}
	return record_file->iov;
}

static ssize_t copy_iov_to_buffer(void *buffer, const struct iovec *iov, int iovcnt)
{
	if ((NULL == iov) || (NULL == buffer)) {
		errno = EFAULT;
		return -1;
	}

	if (iovcnt < 0) {
		errno = EINVAL;
		return -1;
	}

	void *target = buffer;
	for (int i = 0; i < iovcnt; i++) {
		if (NULL == iov[i].iov_base) {
			errno = EFAULT;
			return -1;
		}
		target = mempcpy(target, iov[i].iov_base, iov[i].iov_len);
	}

	return (const char *)target - (const char *)buffer;
}

static ssize_t trace_dumper_writev(int fd, const struct iovec *iov, int iovcnt)
{
    ssize_t length = total_iovec_len(iov, iovcnt);
    void *buffer = malloc(length);
    if (NULL == buffer) {
    	return -1;
    }

    assert(copy_iov_to_buffer(buffer, iov, iovcnt) == length);

    ssize_t bytes_written = TEMP_FAILURE_RETRY(write(fd, buffer, length));
    free(buffer);
    return bytes_written;
}

int write_single_record(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, const struct trace_record *rec)
{
	const size_t len = sizeof(*rec);
	const struct iovec iov = {
			(void *)rec,
			len
	};

	int rc = trace_dumper_write(conf, record_file, &iov, 1, record_file_should_be_parsed(conf, record_file));
    if ((int)len != rc) {
    	if (rc >= 0) { /* Partial write */
    		errno = ETIMEDOUT;
    	}
        return -1;
    }
    return 0;
}

int dump_iovector_to_parser(const struct trace_dumper_configuration_s *conf, struct trace_parser *parser, const struct iovec *iov, int iovcnt)
{
    int i;
    int rc;
    unsigned char accumulated_trace_record[sizeof(struct trace_record)];
    unsigned char *tmp_ptr = accumulated_trace_record;
    unsigned char *iovec_base_ptr;
    for (i = 0; i < iovcnt; i++) {
        iovec_base_ptr = iov[i].iov_base;
        while (1) {
            unsigned int remaining_rec = sizeof(struct trace_record) - (tmp_ptr - accumulated_trace_record);
            unsigned int copy_len = MIN(remaining_rec, iov[i].iov_len - (iovec_base_ptr - (unsigned char *) iov[i].iov_base));
            memcpy(tmp_ptr, iovec_base_ptr, copy_len);
            tmp_ptr += copy_len;
            iovec_base_ptr += copy_len;
            if (tmp_ptr - accumulated_trace_record == sizeof(struct trace_record)) {
                char formatted_record[10 * 1024];
                size_t record_len = 0;
                rc = TRACE_PARSER__process_next_from_memory(parser, (struct trace_record *) accumulated_trace_record, formatted_record, sizeof(formatted_record), &record_len);
                switch (rc) {
                case 0:
					tmp_ptr = accumulated_trace_record;
					if (record_len) {
						if (!conf->syslog) {
							puts(formatted_record);
						} else {
							syslog(LOG_DEBUG, "%s", formatted_record);
						}
					}
					break;

                case ENODATA:  /* End of file */
                	return 0;

                default:
                	syslog(LOG_USER|LOG_ERR, "Trace dumper failed to format a message because of the following error: %s", strerror(errno));
                	return rc;
                }
            }

            if ((unsigned char *)iovec_base_ptr - (unsigned char *)iov[i].iov_base == (unsigned int) iov[i].iov_len) {
                break;
            }
        }
    }

    return 0;
}


static int dump_to_parser_if_necessary(struct trace_dumper_configuration_s *conf, const struct iovec *iov, int iovcnt, bool_t dump_to_parser)
{
	if (dump_to_parser && conf->online && iovcnt > 0) {
	        int parser_rc = dump_iovector_to_parser(conf, &conf->parser, iov, iovcnt);
	        if (parser_rc != 0) {
	        	int err = errno;
				syslog(LOG_USER|LOG_ERR, "trace_dumper: Dumping parsed traces failed due to %s", strerror(err));
				ERR("Dumping parsed traces failed with error", strerror(err));
				return -1;
	        }
	    }

	return 0;
}

static size_t num_records_pending(const struct trace_output_mmap_info *mmap_info);

int trace_dumper_write(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, const struct iovec *iov, int iovcnt, bool_t dump_to_parser)
{
	int ret = -1;
	if (conf->low_latency_write) {
		ret = trace_dumper_write_via_mmapping(conf, record_file, iov, iovcnt);
		if ((ret < 0) && (EAGAIN == errno)) {
			// Controlled data throw. For now just log
			// TODO: Increment a counter in the record file to indicate record loss.
			// NOTE: This should probably be handled at a higher layer.
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
	}
	else {
		ret = trace_dumper_write_via_file_io(conf, record_file, iov, iovcnt);
	}

	dump_to_parser_if_necessary(conf, iov, iovcnt, dump_to_parser);
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

int trace_dumper_write_to_record_file(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, int iovcnt)
{
	int num_warn_bytes = total_iovec_len(record_file->iov, iovcnt);
	if (num_warn_bytes > 0) {
		if (is_closed(record_file)) {
				errno = EBADF;
				return -1;
		}

		if (trace_dumper_write(conf, record_file, record_file->iov, iovcnt, FALSE) != num_warn_bytes) {
			syslog(LOG_USER|LOG_ERR,
					"Trace dumper encountered the following error while writing %d bytes to the file %s: %s",
					num_warn_bytes, record_file->filename, strerror(errno));
			return -1;
		}
    }

	return num_warn_bytes;
}

void trace_dumper_update_written_record_count(struct trace_record_file *record_file)
{
	if (NULL != record_file->mapping_info) {
		record_file->records_written = record_file->mapping_info->records_written;
	}
}

#define ROUND_UP(num, divisor) ((divisor) * (((num) + (divisor) - 1) / (divisor)))
#define ROUND_DOWN(num, divisor) ((num) - (num) % (divisor))


static int free_mmapping(struct trace_output_mmap_info *mmapping) {
	if (NULL == mmapping) {
		errno = EFAULT;
		return -1;
	}

	if ((MAP_FAILED != mmapping->base) && (munmap(mmapping->base, mmapping->mapping_len_bytes) < 0)) {
		return -1;
	}

	if ((mmapping->fd >= 0) && (0 != close(mmapping->fd))) {
		return -1;
	}

	memset(mmapping, -1, sizeof(*mmapping)); /* To catch attempts to access after freeing */
	free(mmapping);
	return 0;
}

static int do_data_sync(struct trace_output_mmap_info *mmap_info, bool_t final)
{
	const trace_record_counter_t records_written = mmap_info->records_written;
	assert(mmap_info->records_committed <= records_written);
	assert(0 == mmap_info->page_size % TRACE_RECORD_SIZE);

	const size_t page_size_records = mmap_info->page_size / TRACE_RECORD_SIZE;
	const struct trace_record *const fadv_base = mmap_info->base + ROUND_DOWN(mmap_info->records_committed, page_size_records);
	const size_t unflushed_bytes = TRACE_RECORD_SIZE * (mmap_info->base + records_written - fadv_base);
	const size_t unflushed_bytes_rounded_to_page 	  = ROUND_DOWN(unflushed_bytes, mmap_info->page_size);
	const size_t unflushed_bytes_rounded_to_preferred = ROUND_DOWN(unflushed_bytes_rounded_to_page, mmap_info->preferred_write_bytes);

	const trace_ts_t now = trace_get_nsec_monotonic();
	size_t fadv_len = 0;
	if (! final) {
		fadv_len = (now >= mmap_info->next_flush_ts) ? unflushed_bytes_rounded_to_page : unflushed_bytes_rounded_to_preferred;
		if (fadv_len <= 0) {
			return EAGAIN;
		}
	}

	assert(mmap_info->records_committed * TRACE_RECORD_SIZE + fadv_len <= mmap_info->mapping_len_bytes);
	const off64_t fadv_start_offset = TRACE_RECORD_SIZE * (fadv_base - mmap_info->base);
	int rc = posix_fadvise64(mmap_info->fd, fadv_start_offset, fadv_len, POSIX_FADV_DONTNEED);
	if (0 != rc) {
		const void *const mapping_base = mmap_info->base;
		ERR("Failed posix_fadvise", fadv_len, fadv_base, mapping_base, rc, strerror(rc));
		syslog(LOG_USER|LOG_ERR, "Failed posix_fadvise of length %#lx at %p, base=%p, due to %s", fadv_len, fadv_base, mapping_base, strerror(rc));
		errno = rc;
		return -1;
	}

	if (final) {
		assert(records_written == mmap_info->records_written);  /* Should not have any further changes if we were really called as final. */
		mmap_info->records_committed = records_written;
		const int lasterr = mmap_info->lasterr;
		const pthread_t posix_tid = mmap_info->tid;
		INFO("Finalizing memory-mapped writing to file", records_written, lasterr, posix_tid);
	}
	else {
		mmap_info->records_committed = (fadv_start_offset + fadv_len) / TRACE_RECORD_SIZE;
		mmap_info->next_flush_ts = now + mmap_info->global_conf->max_flush_interval;
	}
	assert(mmap_info->records_committed <= records_written);

	return 0;
}

static size_t num_records_pending(const struct trace_output_mmap_info *mmap_info)
{
	assert(mmap_info->records_written >= mmap_info->records_committed);
	return mmap_info->records_written - mmap_info->records_committed;
}

static void *msync_mmapped_data(void *mmap_info_vp)
{
	static const useconds_t delay = 1000;
	struct trace_output_mmap_info *mmap_info = (struct trace_output_mmap_info *) mmap_info_vp;
	assert(pthread_self() == mmap_info->tid);
	mmap_info->lasterr = 0;

	do {
		const int rc = do_data_sync(mmap_info, FALSE);
		switch (rc) {
		case 0:  /* Data have been written */
			break;

		default:
			assert(rc < 0);
			mmap_info->lasterr = errno;
			WARN("Worker thread data sync returned", errno, strerror(errno));
			/* No break - also delay as in the case of EAGAIN */

		case EAGAIN:
			usleep(delay);
			break;
		}
	} while (! mmap_info->writing_complete);

	if (ftruncate64(mmap_info->fd, TRACE_RECORD_SIZE * mmap_info->records_written) < 0) {
		ERR("Failed to finalize file size to record count", mmap_info->records_written, errno, strerror(errno));
		syslog(LOG_USER|LOG_ERR, "Failed to truncate the record file with fd=%d to %ld records due to %s",
						mmap_info->fd, mmap_info->records_written, strerror(errno));
	}
	else if (do_data_sync(mmap_info, TRUE) < 0) {
		mmap_info->lasterr = errno;
		syslog(LOG_USER|LOG_ERR, "Failed to commit %ld records at the end of the record file due to %s",
				num_records_pending(mmap_info), strerror(errno));
	}

	if (0 != free_mmapping(mmap_info)) {
		ERR("Failed to free mapping info", errno, strerror(errno));
		syslog(LOG_USER|LOG_ERR, "Failed to free the memory mapping at %p due to %s", mmap_info->base, strerror(errno));
	}

	/* TODO: Use the return value to indicate the number of records lost (if any) */
	return NULL;
}


static int reset_file(const struct trace_record_file *record_file) {
	if (NULL != record_file->mapping_info) {
		record_file->mapping_info->writing_complete = TRUE;
		return TEMP_FAILURE_RETRY(ftruncate64(record_file->fd, record_file->mapping_info->records_committed * TRACE_RECORD_SIZE));
	}

	return 0;
}

static int setup_mmapping(const struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file)
{
	if (is_closed(record_file)) {
		errno = EBADF;
		return -1;
	}

	record_file->mapping_info = calloc(1, sizeof(struct trace_output_mmap_info));
	if (NULL == record_file->mapping_info) {
		return -1;
	}

	const long page_size = sysconf(_SC_PAGESIZE);
	assert(page_size > 0);
	record_file->mapping_info->page_size = (size_t) page_size;
	record_file->mapping_info->preferred_write_bytes = MAX(conf->preferred_flush_bytes, record_file->mapping_info->page_size);
	record_file->mapping_info->global_conf = conf;
	record_file->mapping_info->fd = record_file->fd;
	record_file->mapping_info->next_flush_ts = trace_get_nsec_monotonic() + conf->max_flush_interval;

	const size_t len = ROUND_UP((conf->max_records_per_file + conf->max_records_per_file/4) * TRACE_RECORD_SIZE, record_file->mapping_info->preferred_write_bytes);
	record_file->mapping_info->base = (struct trace_record *)
			mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_SHARED, record_file->fd, 0);
	if (MAP_FAILED == record_file->mapping_info->base) {
		syslog(LOG_USER|LOG_ERR, "Failed mmap with %lu, %d, %d, %d, %d",
				record_file->mapping_info->mapping_len_bytes, PROT_READ|PROT_WRITE, MAP_SHARED, record_file->fd, 0);
		goto free_mapping_info;
	}
	record_file->mapping_info->mapping_len_bytes = len;

	if (0 != ftruncate64(record_file->fd, record_file->mapping_info->mapping_len_bytes)) {
		syslog(LOG_USER|LOG_ERR, "Failed to truncate the file %s to %lu bytes due to %s",
				record_file->filename, record_file->mapping_info->mapping_len_bytes, strerror(errno));
		goto unmap_file;
	}

	int rc = pthread_create(&record_file->mapping_info->tid, NULL, msync_mmapped_data, record_file->mapping_info);
	if (0 != rc) {
		goto errno_from_pthread;
	}

	const char *filename = record_file->filename;
	const void *base_addr = record_file->mapping_info->base;
	const pthread_t posix_tid = record_file->mapping_info->tid;
	INFO("Started worker thread for mmapping", filename, base_addr, posix_tid);

	return 0;

/* Clean-up in case of errors */
errno_from_pthread:
	errno = rc;

unmap_file:
	assert(0 == munmap(record_file->mapping_info->base, record_file->mapping_info->mapping_len_bytes));
	ftruncate(record_file->fd, 0);

free_mapping_info:
	filename = record_file->filename;
	if (0 != close(record_file->fd)) {
		ERR("Failed to close fd", record_file->fd, filename, errno);
	}
	record_file->fd = -1;


	base_addr = record_file->mapping_info->base;
	ERR("Failed to create a memory mapping for", filename, base_addr);

	memset(record_file->mapping_info, -1, sizeof(*(record_file->mapping_info)));
	free(record_file->mapping_info);
	record_file->mapping_info = NULL;
	return -1;
}

static int advise_mmapped_range(struct trace_output_mmap_info *mmap_info, int advice, size_t num_prefetch_records)
{
	const trace_record_counter_t desired_prefetch_end = MIN(mmap_info->mapping_len_bytes / TRACE_RECORD_SIZE, mmap_info->records_written + num_prefetch_records);
	const uintptr_t madv_start = ROUND_DOWN((uintptr_t)(mmap_info->base + mmap_info->records_written), mmap_info->page_size);
	const size_t    madv_len = (uintptr_t)(mmap_info->base + desired_prefetch_end) - madv_start;
	void *const madv_start_vp = (void *)madv_start;

	if (madv_len <= mmap_info->page_size) {
		return EAGAIN;
	}

	const trace_ts_t start = trace_get_nsec_monotonic();
	const trace_record_counter_t mincore_threshold = TRACE_RECORD_BUFFER_RECS;
	if ((POSIX_MADV_WILLNEED == advice) && (num_prefetch_records < mincore_threshold)) {
		const size_t n_pages = (madv_len + mmap_info->page_size - 1) / mmap_info->page_size;
		unsigned char page_residence[n_pages];
		if (0 != mincore(madv_start_vp, madv_len, page_residence)) {
			return -1;
		}

		size_t present;
		for (present = 0; (present < n_pages) && (page_residence[present] & 1); present++)
			;

		const trace_ts_t duration = trace_get_nsec_monotonic() - start;
		if (present == n_pages) {
			DEBUG("mincore saved us an madvise", madv_start_vp, madv_len, num_prefetch_records, advice, duration);
			return 0;
		}
	}

	const int rc = posix_madvise(madv_start_vp, madv_len, advice);
	if (rc != 0) {
		ERR("Attempting to prefetch using posix_madvise(", madv_start_vp, madv_len, advice, ") failed with", rc, strerror(rc));
		errno = rc;
		return -1;
	}
	else {
	    const trace_ts_t duration = trace_get_nsec_monotonic() - start;
	    DEBUG("Prefetched records in output file", madv_start_vp, madv_len, num_prefetch_records, advice, duration);
	}

	return 0;
}

int trace_dumper_prefetch_records_if_necessary(struct trace_output_mmap_info *mmap_info, size_t num_prefetch_records)
{
	const size_t DEFAULT_DESIRED_PREFETCH_RECORDS = 2 * TRACE_RECORD_BUFFER_RECS;
	const size_t prefetch_size = (0 == num_prefetch_records) ? DEFAULT_DESIRED_PREFETCH_RECORDS : num_prefetch_records;
	return advise_mmapped_range(mmap_info, POSIX_MADV_WILLNEED, prefetch_size);
}

static void init_record_timestamps(struct trace_record_file *record_file)
{
	memset(&record_file->ts, 0, sizeof(record_file->ts));
}

static int log_dumper_performance_if_necessary(struct trace_record_file *record_file, size_t n_bytes)
{
	int rc = 0;
	const size_t n_recs_pending = (NULL == record_file->mapping_info) ? 0 : num_records_pending(record_file->mapping_info);
	const struct trace_record_io_timestamps *const ts = &record_file->ts;
	const trace_ts_t memcpy_duration = ts->finished_memcpy - ts->started_memcpy;
	const trace_ts_t validation_duration = ts->finished_validation - ts->started_validation;

	DEBUG("Record writing performance:", memcpy_duration, validation_duration, n_recs_pending);
	if (is_perf_logging_file_open(record_file)) {

		rc = fprintf(record_file->perf_log_file,
				"\"%s\", "
				TRACE_TIMESTAMP_FMT_STRING ", %lu, "
				TRACE_TIMESTAMP_FMT_STRING ", "
				TRACE_TIMESTAMP_FMT_STRING ", %lu\n",
				trace_record_file_basename(record_file),
				ts->started_memcpy,
				n_bytes,
				memcpy_duration,
				validation_duration,
				n_recs_pending);
	}

	return MIN(rc, 0);
}

int trace_dumper_write_via_mmapping(
		const struct trace_dumper_configuration_s *conf,
		struct trace_record_file *record_file,
		const struct iovec *iov,
		int iovcnt)
{
	if ((NULL == record_file->mapping_info) && (setup_mmapping(conf, record_file) < 0)) {
			return -1;
	}
	assert(MAP_FAILED != record_file->mapping_info->base);
	assert(0 != record_file->mapping_info->tid);

	size_t bytes_written = record_file->mapping_info->records_written * TRACE_RECORD_SIZE;
	size_t len = total_iovec_len(iov, iovcnt);
	assert(0 == (len % TRACE_RECORD_SIZE));
	assert(len <= INT_MAX);

	if (len > 0) {
		size_t new_size = bytes_written + len;
		if (new_size > record_file->mapping_info->mapping_len_bytes) {
			errno = EFBIG;
			return -1;
		}

		const trace_record_counter_t recs_written_so_far = record_file->mapping_info->records_written;
		if (num_records_pending(record_file->mapping_info) > conf->max_records_pending_write_via_mmap) {
			trace_record_counter_t records_committed = record_file->mapping_info->records_committed;
			const char *const filename = record_file->filename;
			WARN("Writing backlog exceeded", conf->max_records_pending_write_via_mmap, recs_written_so_far, records_committed, filename);
			errno = EAGAIN;
			return -1;
		}

		init_record_timestamps(record_file);


		struct trace_record *write_start = record_file->mapping_info->base + recs_written_so_far;
		record_file->ts.started_memcpy = trace_get_nsec();
		trace_dumper_prefetch_records_if_necessary(record_file->mapping_info, len / TRACE_RECORD_SIZE);
		assert((size_t)copy_iov_to_buffer(write_start, iov, iovcnt) == len);
		record_file->ts.finished_memcpy = trace_get_nsec();

		if (NULL != record_file->post_write_validator) {
			record_file->ts.started_validation = trace_get_nsec();
			record_file->validator_last_result = record_file->post_write_validator(write_start, len / TRACE_RECORD_SIZE, TRUE, record_file->validator_context);
			record_file->ts.finished_validation = trace_get_nsec();


			const int validation_result = record_file->validator_last_result;
			if (validation_result < 0) {
				ERR("Unrecoverable error while validating records in", record_file->filename, validation_result, recs_written_so_far, write_start, len);
				syslog(LOG_USER|LOG_ERR, "Validation returned error result %d while writing to file %s",
						record_file->validator_last_result, record_file->filename);
				reset_file(record_file);
				return record_file->validator_last_result;
			}
			else if (validation_result > 0) {
				WARN("Invalidated records in file", record_file->filename, validation_result, recs_written_so_far, write_start, len);
			}
		}

		/* Restore the advice for the range written to to MADV_NORMAL. This is done in case a future kernel might have long-term effects after applying the
		 * MADV_WILLNEED advice */
		advise_mmapped_range(record_file->mapping_info, POSIX_MADV_NORMAL, len / TRACE_RECORD_SIZE);

		record_file->mapping_info->records_written += len / TRACE_RECORD_SIZE;
		log_dumper_performance_if_necessary(record_file, len);
	}
	return len;
}

int trace_dumper_flush_mmapping(struct trace_record_file *record_file, bool_t synchronous)
{
	struct trace_output_mmap_info *mapping_info = record_file->mapping_info;
	if (NULL != mapping_info) {
		int rc = 0;
		pthread_t worker_tid = mapping_info->tid;
		int lasterr = mapping_info->lasterr;

		record_file->mapping_info = NULL;
		mapping_info->writing_complete = TRUE;
		mapping_info = NULL;

		const char *action = NULL;
		if (synchronous) {
			rc = pthread_join(worker_tid, NULL);
			action = "joining";
		}
		else {
			rc = pthread_detach(worker_tid);
			action = "detaching";
		}

		if (0 != lasterr) {
			syslog(LOG_WARNING|LOG_USER, "Found lasterr=%d (%s) found while %s the worker thread for the file %s. ",
					lasterr, strerror(lasterr), action, record_file->filename);
		}

		if (0 != rc) {
			syslog(LOG_WARNING|LOG_USER, "Error %d (%s) encountered while %s the worker thread for the file %s.",
					rc, strerror(rc), action, record_file->filename);
			errno = rc;
			return -1;
		}
	}
	return 0;
}

bool_t trace_dumper_record_file_state_is_ok(const struct trace_record_file *record_file)
{
	if (NULL != record_file->mapping_info) {
		return (0 == record_file->mapping_info->lasterr);
	}

	return TRUE;
}
