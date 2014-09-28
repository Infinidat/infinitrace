/*
 * parser_stats.c
 *
 *  Created on: Dec 22, 2013
 *  Original Author: Yotam Rubin, 2012
 *  Maintainer:      Yitzik Casapu, Infinidat
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


#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "platform.h"

#include <sys/types.h>
#ifdef _USE_INOTIFY_
#include <sys/inotify.h>
#endif

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <assert.h>

#include "min_max.h"
#include "array_length.h"
#include "trace_defs.h"
#include "list_template.h"
#include "object_pool.h"
#include "trace_metadata_util.h"
#include "object_pool.h"
#include "trace_str_util.h"
#include "renderer.h"
#include "filter.h"
#include "parser_internal.h"

struct log_occurrences {
    char *tmpl;
    unsigned int occurrences;
    unsigned int cummulative_records;
    trace_log_id_t log_id;
};


typedef struct log_stats {
    struct log_occurrences *logs;
    unsigned int max_log_count;
    unsigned int unique_count;
    unsigned int record_count;
    unsigned long long lost_records;
    unsigned int record_count_by_severity[TRACE_SEV__COUNT];
    struct trace_parser_buffer_context *buffer_context;
} log_stats_t;

OBJECT_POOL(log_stats_pool, log_stats_t, 20);
static log_stats_pool_t log_stats_pool;
#define LOG_STATS_POOL_LENGTH sizeof(log_stats_pool_t) / sizeof(log_stats_pool__element_t)

int compare_log_occurrence_entries(const void *a, const void *b)
{
    const struct log_occurrences *log_occurrence_a = (const struct log_occurrences *) a;
    const struct log_occurrences *log_occurrence_b = (const struct log_occurrences *) b;

    if (log_occurrence_a->occurrences < log_occurrence_b->occurrences) {
        return -1;
    }

    if (log_occurrence_a->occurrences == log_occurrence_b->occurrences) {
        return 0;
    }

    return 1;
}

static void print_underlined(const char *header) {
    puts(header);
    const size_t len = strlen(header);
    char *underline = alloca(len + 1);
    memset(underline, '-', len);
    underline[len] = '\0';
    puts(underline);
}

static void dump_stats_pool(const log_stats_pool_t stats_pool)
{
    unsigned int i, j;
    char header[512];
    const struct log_stats *stats;
    for (i = 0; i < LOG_STATS_POOL_LENGTH; i++) {
        if (!stats_pool[i].allocated) {
            continue;
        }

        snprintf(header, sizeof(header), "Statistics for buffer %s [%d]",
                 stats_pool[i].data.buffer_context->name,
                 stats_pool[i].data.buffer_context->id);
        print_underlined(header);

        stats = &stats_pool[i].data;
        qsort(stats->logs, stats->max_log_count, sizeof(stats->logs[0]), compare_log_occurrence_entries);
        printf("Unique log records count: %d\n", stats->unique_count);
        printf("Record count: %d\n", stats->record_count);
        printf("Lost records: %llu\n", stats->lost_records);
        printf("Records by severity:\n");
        for (j = 0; j < TRACE_SEV__MAX; j++) {
            printf("    %s: %d\n", trace_severity_to_str_array[j], stats->record_count_by_severity[j]);
        }

        for (j = 0; j < stats->max_log_count; j++) {
            const struct log_occurrences *const log = stats->logs + j;
            const unsigned occurrences = log->occurrences;
            if (occurrences > 0) {
                log_id_size_info_output_buf_t size_info;
                log_id_format_sizes(stats->buffer_context, log->log_id, log->cummulative_records * TRACE_RECORD_SIZE / occurrences, size_info);
                printf("%-8d %s : %-100s\n", occurrences, size_info, log->tmpl);
            }
        }

        printf("\n\n");
    }
}

static int restore_parsing_buffer_dump_context(trace_parser_t *parser, const struct buffer_dump_context_s *dump_context)
{
    memcpy(&parser->buffer_dump_context, dump_context, sizeof(parser->buffer_dump_context));
    return TRACE_PARSER__seek(parser, parser->buffer_dump_context.file_offset, SEEK_SET);
}

static int process_all_metadata(trace_parser_t *parser, trace_parser_event_handler_t handler)
{
    struct record_formatting_context_s dump_context;
    struct buffer_dump_context_s orig_dump_context;
    if (parser->stream_type != TRACE_INPUT_STREAM_TYPE_SEEKABLE_FILE) {
        return -1;
    }

    memcpy(&orig_dump_context, &parser->buffer_dump_context, sizeof(orig_dump_context));
    struct trace_record_matcher_spec_s matcher;
    matcher.type = TRACE_MATCHER_FALSE;

    while (1) {
        int rc = process_next_record_from_file(parser, &matcher, handler, &dump_context, NULL);
        if (0 != rc) {
            break;
        }
    }

    restore_parsing_buffer_dump_context(parser, &orig_dump_context);
    return 0;
}

static int dump_metadata(trace_parser_t *parser, enum trace_parser_event_e event, void *event_data, void __attribute__((unused)) *arg)
{
    if (event != TRACE_PARSER_FOUND_METADATA) {
        return 0;
    }

    struct trace_parser_buffer_context *context = (struct trace_parser_buffer_context *) event_data;
    unsigned int i;
    char formatted_template[8192];
    for (i = 0; i < context->metadata->log_descriptor_count; i++) {
        log_id_size_info_output_buf_t size_info;
        log_id_format_sizes(context, i, -1, size_info);
        log_id_to_log_template(parser, context, i, formatted_template, sizeof(formatted_template));
        if (printf("(%05d) %s %s\n", i, size_info, formatted_template) < 0) {
            return -1;
        }
    }

    return 0;
}

int TRACE_PARSER__dump_all_metadata(trace_parser_t *parser)
{
    return process_all_metadata(parser, dump_metadata);
}

static struct log_stats *get_buffer_log_stats(log_stats_pool_t pool, struct trace_parser_buffer_context *buffer)
{
    unsigned int i;
    for (i = 0; i < LOG_STATS_POOL_LENGTH; i++) {
        if (pool[i].allocated && pool[i].data.buffer_context == buffer) {
            return &pool[i].data;
        }
    }

    struct log_stats *stats = log_stats_pool__allocate(pool);
    if (stats == NULL) {
        return NULL;
    }

    stats->logs = calloc(buffer->metadata->log_descriptor_count, sizeof(struct log_occurrences));
    if (NULL == stats->logs) {
        return NULL;
    }

    stats->max_log_count = buffer->metadata->log_descriptor_count;
    stats->buffer_context = buffer;
    return stats;
}

static int count_entries(trace_parser_t *parser, enum trace_parser_event_e event, void *event_data, void __attribute__((unused)) *arg)
{
    log_stats_pool_t *stats_pool = (log_stats_pool_t *) arg;
    struct log_stats *stats;
    char tmpl[8192];

    if (event == TRACE_PARSER_BUFFER_CHUNK_HEADER_PROCESSED) {
        struct parser_buffer_chunk_processed *chunk_processed = (struct parser_buffer_chunk_processed *) event_data;
        stats = get_buffer_log_stats(*stats_pool, chunk_processed->buffer);
        if (NULL == stats) {
            return 0;
        }
        stats->lost_records += chunk_processed->bd->lost_records;
        return 0;
    }

    if (event != TRACE_PARSER_COMPLETE_TYPED_RECORD_PROCESSED) {
        return 0;
    }

    struct parser_complete_typed_record *complete_typed_record = (struct parser_complete_typed_record *) event_data;
    if (!(complete_typed_record->record->termination & TRACE_TERMINATION_LAST)) {
        return 0;
    }

    stats = get_buffer_log_stats(*stats_pool, complete_typed_record->buffer);
    if (NULL == stats) {
        return 0;
    }

    unsigned int metadata_index = complete_typed_record->record->u.typed.log_id;
    assert(metadata_index < stats->max_log_count);

    if (NULL == stats->logs[metadata_index].tmpl) {
        if (log_id_to_log_template(parser, complete_typed_record->buffer, metadata_index, tmpl, sizeof(tmpl)) < 0) {
            return -1;
        }
        stats->logs[metadata_index].tmpl = strdup(tmpl);
        stats->logs[metadata_index].occurrences = 1;
        stats->logs[metadata_index].log_id = metadata_index;
        stats->unique_count++;
    } else {
        assert(stats->logs[metadata_index].occurrences >= 1);
        stats->logs[metadata_index].occurrences++;
    }

    stats->logs[metadata_index].cummulative_records += complete_typed_record->num_phys_records;

    stats->record_count_by_severity[complete_typed_record->record->severity]++;
    return 0;
}

static void free_stats_pool(log_stats_pool_t stats_pool)
{
    unsigned int i;
    for (i = 0; i < LOG_STATS_POOL_LENGTH; i++) {
        if (!stats_pool[i].allocated) {
            continue;
        }

        unsigned int j;
        for (j = 0; j < stats_pool[i].data.max_log_count; j++ ) {
            char *const tmpl = stats_pool[i].data.logs[j].tmpl;
            if (NULL != tmpl) {
                free(tmpl);
            }
        }

        free(stats_pool[i].data.logs);
        log_stats_pool__deallocate(stats_pool, &(stats_pool[i].data));
    }
}

static void possibly_display_filename_for_statistics(trace_parser_t *parser) {
    if (parser->show_filename) {
        out_fd_t out;
        out_init(&out);
        say_new_file(&out, parser, 0);
        out_flush(&out);
    }
}

static double percentage(trace_record_counter_t num, trace_record_counter_t denom)
{
    return (100.0 * num) / denom;
}

static void dump_global_stats(const trace_parser_t *parser)
{
    print_underlined("Global statistics");
    const trace_record_counter_t total_records = parser->file_info.end_offset / TRACE_RECORD_SIZE;

#define PCT_FMT "%.1f%%"
    printf("Total records in file: %lu\n", total_records);
    printf("Total metadata records: %lu (" PCT_FMT ")\n", parser->global_stats.n_metadata_records, percentage(parser->global_stats.n_metadata_records, total_records));
    if (parser->global_stats.n_chunks > 0) {
        printf("Total typed records (possiblly compressed): %lu (" PCT_FMT ")\n", parser->global_stats.n_compressed_typed_records, percentage(parser->global_stats.n_compressed_typed_records, total_records));
        const trace_record_counter_t n_header_records = total_records - parser->global_stats.n_metadata_records - parser->global_stats.n_compressed_typed_records;
        printf("Total header records:  %lu (" PCT_FMT ")\n", n_header_records, percentage(n_header_records, total_records));
        printf("Total typed records uncompressed: %lu\n", parser->global_stats.n_uncompressed_typed_records);
        if (parser->global_stats.n_uncompressed_typed_records > 0) {
            const double net_compression_ratio   = percentage(parser->global_stats.n_compressed_typed_records, parser->global_stats.n_uncompressed_typed_records);
            const double gross_compression_ratio =
                    percentage(total_records, total_records + parser->global_stats.n_uncompressed_typed_records - parser->global_stats.n_compressed_typed_records);
            printf("Compression ratios: net - " PCT_FMT ", gross - " PCT_FMT "\n", net_compression_ratio, gross_compression_ratio);
        }
    }

#undef PCT_FMT
}

int TRACE_PARSER__dump_statistics(trace_parser_t *parser)
{
    if (parser->stream_type != TRACE_INPUT_STREAM_TYPE_SEEKABLE_FILE) {
        errno = EINVAL;
        return -1;
    }

    log_stats_pool__init(log_stats_pool);
    unsigned int count = 0;
    while (1) {
        int rc = process_next_record_from_file(parser, parser->record_filter, count_entries, (void *) log_stats_pool, NULL);
        count++;
        if (0 != rc) {
            if (ENODATA != rc) {
                return rc;
            }
            break;
        }
    }


    possibly_display_filename_for_statistics(parser);
    dump_stats_pool(log_stats_pool);
    free_stats_pool(log_stats_pool);
    dump_global_stats(parser);
    return 0;
}
