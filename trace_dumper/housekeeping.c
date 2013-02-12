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

#include <syslog.h>
#include <errno.h>

#include "../trace_lib.h"
#include "../trace_user.h"
#include "../trace_clock.h"
#include "../trace_str_util.h"
#include "trace_dumper.h"
#include "writer.h"
#include "write_prep.h"
#include "buffers.h"
#include "open_close.h"
#include "housekeeping.h"

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
    if ((NULL != conf->record_file.mapping_info) && (trace_dumper_prefetch_records_if_necessary(conf->record_file.mapping_info, 0) < 0)) {
        rc = -1;
    }

    if ((NULL != conf->notification_file.mapping_info) && (trace_dumper_prefetch_records_if_necessary(conf->notification_file.mapping_info, 0x400) < 0)) {
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
        INFO("total deltas", total_deltas[i], rid + 1, i, TRACE_BUFFER_NUM_RECORDS);

        /* If after adding up all the records this buffer has nothing left to write discard it. */
        if ((rid + 1 == TRACE_BUFFER_NUM_RECORDS) && (total_deltas[i] == 0)) {
            discard_buffer(conf, mapped_buffer);
        }
    }

    return 0;
}

int do_housekeeping_if_necessary(struct trace_dumper_configuration_s *conf)
{
    apply_requested_file_operations(conf, TRACE_REQ_CLOSE_ALL_FILES | TRACE_REQ_DISCARD_ALL_BUFFERS);

    const trace_ts_t HOUSEKEEPING_INTERVAL = 10000000; /* 10ms */
    const trace_ts_t now = get_nsec_monotonic();
    if (now < conf->next_housekeeping_ts) {
        return EAGAIN;
    }
    conf->next_housekeeping_ts = now + HOUSEKEEPING_INTERVAL;

    int rc = reap_empty_dead_buffers(conf);
    if (0 != rc) {
        syslog(LOG_USER|LOG_ERR, "trace_dumper: Error %s encountered while emptying dead buffers.", strerror(errno));
        return rc;
    }

    handle_overwrite(conf);
    apply_requested_file_operations(conf, TRACE_REQ_ALL_OPS);

    if (!conf->attach_to_pid && !conf->stopping) {
        rc = map_new_buffers(conf);
        if (0 != rc) {
            syslog(LOG_USER|LOG_ERR, "trace_dumper: Error %s encountered while mapping new buffers.", strerror(errno));
            return rc;
        }
    }

    rc = unmap_discarded_buffers(conf);
    if (0 != rc) {
        syslog(LOG_USER|LOG_ERR, "trace_dumper: Error %s encountered while unmapping discarded buffers.", strerror(errno));
        return rc;
    }

    rc = prefetch_mmapped_pages(conf);
    if (0 != rc) {
        ERR("Prefetching mapped pages returned", rc, errno, strerror(errno));
        syslog(LOG_ERR|LOG_USER, "Prefetching mapped pages returned %d, errno=%d (%s)", rc, errno, strerror(errno));
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

