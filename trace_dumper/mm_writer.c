/*
 * mm_writer.c
 *
 * Routines for writing trace files via memory mappings
 *
 *  Created on: Oct 17, 2013
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
#include "../platform.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

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
#include "open_close.h"
#include "events.h"
#include "sgio_util.h"
#include "mm_writer.h"

void trace_mm_writer_update_written_record_count(struct trace_record_file *record_file)
{
    if (trace_is_record_file_using_mm(record_file)) {
        record_file->records_written = record_file->mapping_info->records_written;
    }
}

#define ROUND_UP(num, divisor) ((divisor) * (((num) + (divisor) - 1) / (divisor)))
#define ROUND_DOWN(num, divisor) ((num) - (num) % (divisor))


static void free_mmapping_allocated_mem(struct trace_output_mmap_info *mmapping)
{
    if (NULL != mmapping) {
        if (NULL != mmapping->filename) {
            free((void*) (mmapping->filename));
        }
        memset(mmapping, -1, sizeof(*mmapping)); /* To catch attempts to access after freeing */
        free(mmapping);
    }
}

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

    trace_event_details_t details = { .filename = mmapping->filename };
    trace_send_event(TRACE_FILE_CLOSED, &details);

    free_mmapping_allocated_mem(mmapping);
    return 0;
}

static int do_data_sync(struct trace_output_mmap_info *mmap_info, bool_t final)
{
    const trace_record_counter_t records_written = mmap_info->records_written;
    TRACE_ASSERT(mmap_info->records_committed <= records_written);
    TRACE_ASSERT(0 == mmap_info->page_size % TRACE_RECORD_SIZE);

    const size_t page_size_records = mmap_info->page_size / TRACE_RECORD_SIZE;
    const struct trace_record *const fadv_base = mmap_info->base + ROUND_DOWN(mmap_info->records_committed, page_size_records);
    const size_t unflushed_bytes = TRACE_RECORD_SIZE * (mmap_info->base + records_written - fadv_base);
    const size_t unflushed_bytes_rounded_to_page      = ROUND_DOWN(unflushed_bytes, mmap_info->page_size);
    const size_t unflushed_bytes_rounded_to_preferred = ROUND_DOWN(unflushed_bytes_rounded_to_page, mmap_info->preferred_write_bytes);

    const trace_ts_t now = trace_get_nsec_monotonic();
    size_t fadv_len = 0;
    if (! final) {
        fadv_len = (now >= mmap_info->next_flush_ts) ? unflushed_bytes_rounded_to_page : unflushed_bytes_rounded_to_preferred;
        if (fadv_len <= 0) {
            return EAGAIN;
        }
    }

    TRACE_ASSERT(mmap_info->records_committed * TRACE_RECORD_SIZE + fadv_len <= mmap_info->mapping_len_bytes);
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
        TRACE_ASSERT(records_written == mmap_info->records_written);  /* Should not have any further changes if we were really called as final. */
        mmap_info->records_committed = records_written;
        const int lasterr = mmap_info->lasterr;
        const pthread_t posix_tid = mmap_info->tid;
        INFO("Finalizing memory-mapped writing to file", records_written, lasterr, posix_tid);
    }
    else {
        mmap_info->records_committed = (fadv_start_offset + fadv_len) / TRACE_RECORD_SIZE;
        mmap_info->next_flush_ts = now + mmap_info->global_conf->max_flush_interval;
    }
    TRACE_ASSERT(mmap_info->records_committed <= records_written);

    return 0;
}

size_t num_records_pending(const struct trace_output_mmap_info *mmap_info)
{
    TRACE_ASSERT(mmap_info->records_written >= mmap_info->records_committed);
    return mmap_info->records_written - mmap_info->records_committed;
}

static void *msync_mmapped_data(void *mmap_info_vp)
{
    static const useconds_t delay = 1000;
    struct trace_output_mmap_info *mmap_info = (struct trace_output_mmap_info *) mmap_info_vp;
    TRACE_ASSERT(pthread_self() == mmap_info->tid);
    mmap_info->lasterr = 0;

    do {
        const int rc = do_data_sync(mmap_info, FALSE);
        switch (rc) {
        case 0:  /* Data have been written */
            break;

        default:
            TRACE_ASSERT(rc < 0);
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

static bool_t record_file_name_is_fixed(const struct trace_dumper_configuration_s *conf, const struct trace_record_file *record_file)
{
    return  ((record_file == &conf->record_file)       && conf->fixed_output_filename) ||
            ((record_file == &conf->notification_file) && (conf->fixed_notification_filename));
}

static int prevent_mmapping_copy_across_fork(const struct trace_output_mmap_info *mapping_info)
{
    int rc;
    void *const base_addr = mapping_info->base;
#ifdef MADV_DONTFORK
    rc = madvise(base_addr, mapping_info->mapping_len_bytes, MADV_DONTFORK);
#else
    errno = ENOSYS;
    rc = -1;
#endif

    if (0 != rc) {
        const int err = errno;
        syslog(LOG_USER|LOG_WARNING, "Failed to make memory mapping %p unavailable across forks due to error %d - %s", base_addr, err, strerror(err));
        WARN("Failed to make memory mapping", base_addr, "unavailable across forks due to", err, strerror(err));
    }

    return rc;
}

static int setup_mmapping(const struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file)
{
    if (is_closed(record_file)) {
        errno = EBADF;
        return -1;
    }
    const char *const filename = record_file->filename;

    record_file->mapping_info = calloc(1, sizeof(struct trace_output_mmap_info));
    if (NULL == record_file->mapping_info) {
        return -1;
    }

    const long page_size = sysconf(_SC_PAGESIZE);
    TRACE_ASSERT(page_size > 0);
    record_file->mapping_info->page_size = (size_t) page_size;
    record_file->mapping_info->preferred_write_bytes = MAX(conf->preferred_flush_bytes, record_file->mapping_info->page_size);
    record_file->mapping_info->global_conf = conf;
    record_file->mapping_info->fd = record_file->fd;
    record_file->mapping_info->next_flush_ts = trace_get_nsec_monotonic() + conf->max_flush_interval;

    const size_t mmapping_len_records = record_file_name_is_fixed(conf, record_file) ?
            16 * conf->max_records_per_file :
            conf->max_records_per_file + conf->max_records_per_file/4;
    const size_t len = ROUND_UP(mmapping_len_records * TRACE_RECORD_SIZE, record_file->mapping_info->preferred_write_bytes);
    record_file->mapping_info->base = (struct trace_record *)
            mmap(NULL, len, PROT_READ|PROT_WRITE, MAP_SHARED, record_file->fd, 0);
    if (MAP_FAILED == record_file->mapping_info->base) {
        syslog(LOG_USER|LOG_ERR, "Failed mmap with %lu, %d, %d, %d, %d",
                record_file->mapping_info->mapping_len_bytes, PROT_READ|PROT_WRITE, MAP_SHARED, record_file->fd, 0);
        goto free_mapping_info;
    }
    record_file->mapping_info->mapping_len_bytes = len;
    prevent_mmapping_copy_across_fork(record_file->mapping_info);

    if (0 != ftruncate64(record_file->fd, record_file->mapping_info->mapping_len_bytes)) {
        syslog(LOG_USER|LOG_ERR, "Failed to truncate the file %s to %lu bytes due to %s",
                record_file->filename, record_file->mapping_info->mapping_len_bytes, strerror(errno));
        goto unmap_file;
    }

    if (NULL != filename) {
        record_file->mapping_info->filename = strdup(filename);
        if (NULL == record_file->mapping_info->filename) {
            goto unmap_file;
        }
    }

    int rc = pthread_create(&record_file->mapping_info->tid, NULL, msync_mmapped_data, record_file->mapping_info);
    if (0 != rc) {
        goto errno_from_pthread;
    }


    const void *base_addr = record_file->mapping_info->base;
    const pthread_t posix_tid = record_file->mapping_info->tid;
    INFO("Started worker thread for mmapping", filename, base_addr, posix_tid);

    return 0;

/* Clean-up in case of errors */
errno_from_pthread:
    errno = rc;

unmap_file:
    TRACE_ASSERT(0 == munmap(record_file->mapping_info->base, record_file->mapping_info->mapping_len_bytes));
    ftruncate(record_file->fd, 0);

free_mapping_info:
    base_addr = record_file->mapping_info->base;
    ERR("Failed to create a memory mapping for", filename, TRACE_NAMED_PARAM(fd, record_file->fd),
            base_addr, TRACE_NAMED_PARAM(mapping_len, record_file->mapping_info->mapping_len_bytes));

    if (0 != close(record_file->fd)) {
        ERR("Failed to close fd", record_file->fd, filename, errno);
    }
    record_file->fd = -1;

    free_mmapping_allocated_mem(record_file->mapping_info);
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
            ERR("Failed to set-up mmapping errno=", errno, strerror(errno), record_file->filename);
            return -1;
    }
    TRACE_ASSERT(MAP_FAILED != record_file->mapping_info->base);
    TRACE_ASSERT(0 != record_file->mapping_info->tid);

    size_t bytes_written = record_file->mapping_info->records_written * TRACE_RECORD_SIZE;
    size_t len = total_iovec_len(iov, iovcnt);
    TRACE_ASSERT(0 == (len % TRACE_RECORD_SIZE));
    TRACE_ASSERT(len <= INT_MAX);

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
        TRACE_ASSERT((size_t)copy_iov_to_buffer(write_start, iov, iovcnt) == len);
        record_file->ts.finished_memcpy = trace_get_nsec();

        if (NULL != record_file->post_write_validator) {
            record_file->ts.started_validation = trace_get_nsec();
            record_file->validator_last_result = record_file->post_write_validator(
                    write_start, len / TRACE_RECORD_SIZE, TRACE_VALIDATOR_FIX_ERRORS ^ record_file->validator_flags_override, record_file->validator_context);
            record_file->ts.finished_validation = trace_get_nsec();


            const int validation_result = record_file->validator_last_result;
            if (validation_result < 0) {
                ERR("Unrecoverable error while validating records in", record_file->filename, validation_result, recs_written_so_far, write_start, len);
                syslog(LOG_USER|LOG_ERR, "Validation returned error result %d while writing to file %s",
                        record_file->validator_last_result, record_file->filename);
                record_file->mapping_info->lasterr = errno;
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
        const pthread_t worker_tid = mapping_info->tid;
        const int lasterr = mapping_info->lasterr;

        record_file->mapping_info = NULL;
        mapping_info->writing_complete = TRUE;
        INFO("Flushing the mapping for the file", record_file->filename, TRACE_NAMED_PARAM(fd, record_file->fd),
                synchronous, mapping_info, TRACE_NAMED_PARAM(tid, mapping_info->tid));
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
            WARN("Detected error", lasterr, "while", action, "the thread", worker_tid);
            syslog(LOG_WARNING|LOG_USER, "Found lasterr=%d (%s) found while %s the worker thread for the file %s. ",
                    lasterr, strerror(lasterr), action, record_file->filename);
        }

        if (0 != rc) {
            ERR("Error while", action, "the thread", worker_tid, rc);
            syslog(LOG_WARNING|LOG_USER, "Error %d (%s) encountered while %s the worker thread for the file %s.",
                    rc, strerror(rc), action, record_file->filename);
            errno = rc;
            return -1;
        }
    }
    else {
        INFO("Not flushing the file which has no memory mapping defined", record_file->filename, TRACE_NAMED_PARAM(fd, record_file->fd));
    }
    return 0;
}
