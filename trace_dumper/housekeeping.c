/*
 * housekeeping.c:  Routines run periodically for dumper maintenance and diagnostic output.
 *
 *      File Created on: Feb 3, 2013 by Yitzik Casapu, Infinidat
 *      Original Author: Yotam Rubin, 2012
 *      Maintainer:      Yitzik Casapu, Infinidat
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

#include <syslog.h>
#include <errno.h>
#include <unistd.h>

#include "../trace_lib.h"
#include "../trace_user.h"
#include "../trace_clock.h"
#include "../trace_str_util.h"
#include "trace_dumper.h"
#include "mm_writer.h"
#include "writer.h"
#include "write_prep.h"
#include "sgio_util.h"
#include "internal_buffer.h"
#include "buffers.h"
#include "open_close.h"
#include "metadata.h"
#include "sgio_util.h"
#include "housekeeping.h"

#define COLOR_BOOL conf->color
#include "../colors.h"

/* Housekeeping routines */

static void handle_overwrite(struct trace_dumper_configuration_s *conf)
{
    if (!conf->max_records_per_second)  {
        return;
    }

    unsigned long long current_time = get_nsec_monotonic();
    DEBUG("Checking overrwrite. Wrote", conf->record_file.records_written - conf->last_overwrite_test_record_count,
          "records in a second. Minimal severity is now", conf->minimal_allowed_severity);
    if (current_time - conf->last_overwrite_test_time < TRACE_SECOND) {
        return;
    }

    if (conf->record_file.records_written - conf->last_overwrite_test_record_count > conf->max_records_per_second) {
        conf->minimal_allowed_severity = __TRACE_STDC_MIN(conf->minimal_allowed_severity + 1, TRACE_SEV__MAX);
        conf->next_possible_overwrite_relaxation = current_time + RELAXATION_BACKOFF;
        WARN("Overrwrite occurred. Wrote", conf->record_file.records_written - conf->last_overwrite_test_record_count,
             "records in a second. Minimal severity is now", conf->minimal_allowed_severity);
    } else {
        if (conf->minimal_allowed_severity && (current_time > conf->next_possible_overwrite_relaxation)) {
            conf->minimal_allowed_severity = __TRACE_STDC_MAX(conf->minimal_allowed_severity - 1, 0);
            INFO("Relaxing overwrite filter. Write", conf->record_file.records_written - conf->last_overwrite_test_record_count,
                 "records in a second. Minimal severity is now", conf->minimal_allowed_severity);
        }
    }

    conf->last_overwrite_test_time = current_time;
    conf->last_overwrite_test_record_count = conf->record_file.records_written;
}

static int prefetch_mmapped_pages(struct trace_dumper_configuration_s *conf)
{
    int rc = 0;
    if (trace_is_record_file_using_mm(&conf->record_file) && (trace_dumper_prefetch_records_if_necessary(conf->record_file.mapping_info, 0) < 0)) {
        rc = -1;
    }

    if (trace_is_record_file_using_mm(&conf->notification_file) && (trace_dumper_prefetch_records_if_necessary(conf->notification_file.mapping_info, 0x400) < 0)) {
        rc = -1;
    }

    return rc;
}


static int reap_empty_dead_buffers(struct trace_dumper_configuration_s *conf)
{
    struct trace_mapped_buffer *mapped_buffer = NULL;
    const struct trace_mapped_records *mapped_records = NULL;
    int i, rid;
    unsigned long long total_deltas[MappedBuffers_NUM_ELEMENTS];
    struct records_pending_write deltas;
    memset(total_deltas, 0, sizeof(total_deltas));

    for_each_mapped_records(i, rid, mapped_buffer, mapped_records) {
        if (!mapped_buffer->dead) {
            continue;
        }

        calculate_delta(mapped_records, &deltas);

        /* Add-up the total number of unwritten records in the buffer */
        total_deltas[i] += deltas.total;
        DEBUG("total deltas", total_deltas[i], rid + 1, i, TRACE_BUFFER_NUM_RECORDS);

        /* If after adding up all the records this buffer has nothing left to write discard it. */
        if ((rid + 1 == TRACE_BUFFER_NUM_RECORDS) && (total_deltas[i] == 0)) {
            discard_buffer(conf, mapped_buffer);
        }
    }

    return 0;
}

static int internal_buf_flush_completion(struct trace_record_file *record_file, struct aiocb *cb)
{
    const bool_t same_file = (cb->aio_fildes == record_file->fd);
    TRACE_ASSERT(((trace_record_counter_t) (cb->aio_offset) == record_file->records_written * TRACE_RECORD_SIZE) || !same_file);

    int err = aio_error(cb);
    switch (err) {
    case 0: {
        const ssize_t bytes_written = aio_return(cb);
        TRACE_ASSERT(bytes_written >= 0);
        if ((size_t) bytes_written == cb->aio_nbytes) {
            internal_buf_commit_read(record_file->internal_buf);
            record_file->records_written += trace_dumper_async_num_recs_pending_active_file(record_file);
            return 0;
        }
        else {
            TRACE_ASSERT((size_t) bytes_written < cb->aio_nbytes);
            WARN("Async write only wrote", bytes_written, "<", cb->aio_nbytes, "to", record_file->filename, record_file->fd, "rolling back");
            err = ETIMEDOUT;
        }
        }
        break;

    case EINPROGRESS:
        ERR("Flush completion routine called while AIO is still in progress for", record_file->filename);
        return -1;

    case ECANCELED:
        INFO("Async file write canceled fd=", cb->aio_fildes, "record_file:", record_file->fd, record_file->filename, "size=", cb->aio_offset);
        break;

    case ENOSPC:
        ERR("Aysnc write has failed due to no space");
        /* TODO: Implement an anti-flooding mechanism */
        /* no break - continue as for other error conditions */

    default:
        TRACE_ASSERT(aio_return(cb) < 0);
        break;
    }

    internal_buf_rollback_read(record_file->internal_buf);
    if (ftruncate64(cb->aio_fildes, cb->aio_offset) < 0) {
        WARN("Could not truncate the file async_fd=", cb->aio_fildes, "record_file:", record_file->fd, record_file->filename, "to size", cb->aio_offset);
    }
    errno = err;
    return -1;
}

static int flush_internal_buffer(struct trace_dumper_configuration_s *conf)
{
    int rc = 0;
    if (conf->record_file.internal_buf) {
        if (    (trace_dumper_net_num_records_pending(&conf->record_file) > 0) &&
                (NULL != trace_dumper_get_vacant_aiocb(&conf->record_file, conf->async_io_wait))) {
            struct iovec iov;
            if (!internal_buf_contiguous_pending_read_as_iov(conf->record_file.internal_buf, &iov)) {
                DEBUG("Wrap around while reading internal buffer");
            }

            if (iov.iov_len > 0) {
                conf->record_file.async_completion_routine = internal_buf_flush_completion;
                rc = trace_dumper_write_async_if_possible(conf, &conf->record_file, (struct trace_record *)(iov.iov_base), iov.iov_len / TRACE_RECORD_SIZE);
                if ((rc < 0) && trace_dumper_async_timed_out()) {
                    rc = EAGAIN;
                }
            }
        }
    }

    return rc;
}

static int dump_new_metadata(struct trace_dumper_configuration_s *conf)
{
    struct trace_mapped_buffer *mapped_buffer = NULL;
    int i = 0;
    for_each_mapped_buffer(i, mapped_buffer) {
        const int rc = dump_metadata_if_necessary(conf, mapped_buffer);
        if (0 != rc) {
            if (trace_dumper_async_timed_out()) {
                return EAGAIN;
            }
            ERR("Failed to dump new metadata for pid", mapped_buffer->pid, mapped_buffer->name, "due to error", errno, strerror(errno));
            return rc;
        }
    }

    return 0;
}

int do_housekeeping_if_necessary(struct trace_dumper_configuration_s *conf)
{
    int rc = flush_internal_buffer(conf);
    if (0 != rc) {
        return rc;
    }

    apply_requested_file_operations(conf, TRACE_REQ_CLOSE_ALL_FILES | TRACE_REQ_DISCARD_ALL_BUFFERS);

    const trace_ts_t HOUSEKEEPING_INTERVAL = 10 * TRACE_MS;
    const trace_ts_t now = get_nsec_monotonic();
    if (now < conf->next_housekeeping_ts) {
        return EAGAIN;
    }
    conf->next_housekeeping_ts = now + HOUSEKEEPING_INTERVAL;

    rc = reap_empty_dead_buffers(conf);
    if (0 != rc) {
        ERR("reap_empty_dead_buffers returned", rc, TRACE_NAMED_PARAM(errno, errno), strerror(errno));
        syslog(LOG_USER|LOG_ERR, "trace_dumper: Error %s encountered while emptying dead buffers.", strerror(errno));
        return rc;
    }

    handle_overwrite(conf);
    apply_requested_file_operations(conf, TRACE_REQ_ALL_OPS);

    if (!conf->stopping) {
        rc = map_new_buffers(conf);
        if (0 != rc) {
            ERR("map_new_buffers returned", rc, TRACE_NAMED_PARAM(errno, errno), strerror(errno));
            syslog(LOG_USER|LOG_ERR, "trace_dumper: Error %s encountered while mapping new buffers.", strerror(errno));
            return rc;
        }

        rc = dump_new_metadata(conf);
        if (0 != rc) {
            return rc;
        }
    }

    rc = unmap_discarded_buffers(conf);
    if (0 != rc) {
        ERR("unmap_discarded_buffers returned", rc, TRACE_NAMED_PARAM(errno, errno), strerror(errno));
        syslog(LOG_USER|LOG_ERR, "trace_dumper: Error %s encountered while unmapping discarded buffers.", strerror(errno));
        return rc;
    }

    rc = prefetch_mmapped_pages(conf);
    if (0 != rc) {
        ERR("Prefetching mapped pages returned", rc, TRACE_NAMED_PARAM(errno, errno), strerror(errno));
        syslog(LOG_ERR|LOG_USER, "Prefetching mapped pages returned %d, errno=%d (%s)", rc, errno, strerror(errno));
    }

    if (conf->log_details) {
        DEBUG("Finished housekeeping with", rc, TRACE_NAMED_PARAM(next_ts, conf->next_housekeeping_ts));
    }
    return rc;
}

/* Online statistics collection */

static void severity_type_to_str(unsigned int severity_type, char *severity_str, unsigned int severity_str_size)
{
    int i;
    unsigned int first_element = 1;
    memset(severity_str, 0, severity_str_size);
    for (i = TRACE_SEV__MIN; i <= TRACE_SEV__MAX; i++) {
        if (severity_type & (1 << i)) {
            if (!first_element) {
                strncat(severity_str, ", ", severity_str_size);
            }
            strncat(severity_str, trace_severity_to_str_array[i], severity_str_size - 1 - strlen(severity_str));
            first_element = 0;
        }
    }
}

void dump_online_statistics(const struct trace_dumper_configuration_s *conf)
{
    char display_bar[60];
    char severity_type_str[100];
    unsigned int current_display_index = 0;
    unsigned int next_display_record = 0;
    unsigned int unflushed_records = 0;
    int i;
    unsigned int j;
    int rid;
    struct trace_mapped_buffer *mapped_buffer;
    const struct trace_mapped_records *mapped_records;

    for_each_mapped_records(i, rid, mapped_buffer, mapped_records) {
        current_display_index = 0;
        memset(display_bar, '_', sizeof(display_bar));
        display_bar[sizeof(display_bar) - 1] = '\0';
        unflushed_records = 0;
        next_display_record = 0;
        unsigned int display_resolution = mapped_records->imutab->max_records / sizeof(display_bar);
        for (j = 0; j < mapped_records->imutab->max_records; j++) {
            trace_ts_t ts = mapped_records->records[j].ts;

            if (j > next_display_record) {
                next_display_record += display_resolution;
                current_display_index++;
            }

            if (!ts) {
                continue;
            }

            if (ts > mapped_records->mutab->latest_flushed_ts) {
                unflushed_records++;
                display_bar[current_display_index] = '#';
            }
        }

        severity_type_to_str(mapped_records->imutab->severity_type, severity_type_str, sizeof(severity_type_str));
        unsigned int usage_percent = unflushed_records / (mapped_records->imutab->max_records / 100);
        char formatted_usage[15];
        if (usage_percent < 50) {
            snprintf(formatted_usage, sizeof(formatted_usage), _F_GREEN("%%%03d"), usage_percent);
        } else if (usage_percent >= 50 && usage_percent < 80) {
            snprintf(formatted_usage, sizeof(formatted_usage), _F_YELLOW_BOLD("%%%03d"), usage_percent);
        } else {
            snprintf(formatted_usage, sizeof(formatted_usage), _F_RED_BOLD("%%%03d"), usage_percent);
        }

        printf(_F_MAGENTA("%-16s") _F_GREEN("%-24s") _ANSI_DEFAULTS("[") _F_YELLOW_BOLD("%d") _ANSI_DEFAULTS("]") _ANSI_DEFAULTS("[") _F_BLUE_BOLD("%07x") _ANSI_DEFAULTS("/") _F_BLUE_BOLD("%07x") _ANSI_DEFAULTS("]") "    (%s" _ANSI_DEFAULTS(")") _ANSI_DEFAULTS(" ") "(%s) \n", mapped_buffer->name, severity_type_str, mapped_buffer->pid, unflushed_records, mapped_records->imutab->max_records, formatted_usage, display_bar);
    }
}

void possibly_dump_online_statistics(struct trace_dumper_configuration_s *conf)
{
    static const unsigned long long STATS_DUMP_DELTA = TRACE_SECOND * 3;

    trace_ts_t current_time = get_nsec_monotonic();
    if (! (conf->dump_online_statistics && current_time > conf->next_stats_dump_ts)) {
        return;
    }

    printf("%s %s", CLEAR_SCREEN, GOTO_TOP);
    dump_online_statistics(conf);

    conf->next_stats_dump_ts = current_time + STATS_DUMP_DELTA;
}

