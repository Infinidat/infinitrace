/***
Copyright 2012 Yotam Rubin <yotamrubin@gmail.com>
   Sponsored by infinidat (http://infinidat.com)
   
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
***/

#ifndef __TRACE_PARSER_H__
#define __TRACE_PARSER_H__

#include "list_template.h"
#include <stdio.h>
#include "trace_defs.h"
#include "hashmap.h"


#ifdef __cplusplus
extern "C" {
#endif

struct trace_parser_buffer_context {
    struct trace_metadata_region *metadata;
    map_t type_hash;
    unsigned long metadata_size;
    unsigned long current_metadata_offset;
    unsigned long metadata_read;
    size_t metadata_log_desciptor_size;
    struct trace_log_descriptor *descriptors;
    struct trace_type_definition *types;
    char name[0x100];
    unsigned int id;
};

#define MAX_ACCUMULATORS (100)
#define MAX_ACCUMULATED_DATA (2048 * 20)
struct trace_record_accumulator {
    char accumulated_data[MAX_ACCUMULATED_DATA];
    unsigned int data_offset;
    trace_pid_t tid;
    trace_ts_t  ts;
    enum trace_severity severity;
    trace_log_id_t log_id;
};

CREATE_LIST_PROTOTYPE(BufferParseContextList, struct trace_parser_buffer_context, 100)
CREATE_LIST_PROTOTYPE(RecordsAccumulatorList, struct trace_record_accumulator, BufferParseContextList_NUM_ELEMENTS)

struct parser_complete_typed_record {
    struct trace_record *record;
    struct trace_parser_buffer_context *buffer;
    unsigned num_phys_records;
};

struct parser_buffer_chunk_processed {
    struct trace_record_buffer_dump *bd;
    struct trace_parser_buffer_context *buffer;
};
    
struct trace_file_info {
    char filename[0x100];
    char machine_id[0x100];
    long long current_offset;
    long long end_offset;
    int fd;
    void *file_base;
    unsigned short format_version;
    bool_t low_latency_mode;
};

enum trace_parser_event_e {
    TRACE_PARSER_COMPLETE_TYPED_RECORD_PROCESSED,
    TRACE_PARSER_MATCHED_RECORD,
    TRACE_PARSER_SEARCHING_METADATA,
    TRACE_PARSER_OPERATION_IN_PROGRESS,
    TRACE_PARSER_UNKNOWN_RECORD_ENCOUNTERED,
    TRACE_PARSER_FOUND_METADATA,
    TRACE_PARSER_BUFFER_CHUNK_HEADER_PROCESSED,
};

enum trace_input_stream_type {
    TRACE_INPUT_STREAM_TYPE_NONSEEKABLE,
    TRACE_INPUT_STREAM_TYPE_SEEKABLE_FILE
};

enum trace_parser_param_name_disp_mode {
    TRACE_PARSER_PARAM_NAME_DISP_NONE = 0,
    TRACE_PARSER_PARAM_NAME_DISP_ALL = 1,
    TRACE_PARSER_PARAM_NAME_DISP_EXPLICIT,
    TRACE_PARSER_PARAM_NAME_DISP_LAST_FIELD,
};

struct record_formatting_context_s {
    int tail;
    int current_severity;
    char formatted_record[1024 * 20];
};


#define RECORD_DUMP_CONTEXTS (150)
struct record_dump_context_s {
    off64_t start_offset;
    off64_t current_offset;
    off64_t end_offset;
    const struct trace_record *uncompressed_data;
    unsigned flags;
};

struct buffer_dump_context_s {
    struct record_dump_context_s record_dump_contexts[RECORD_DUMP_CONTEXTS];
    off64_t end_offset;
    off64_t previous_dump_offset;
    off64_t file_offset;
    unsigned int num_chunks;
};

struct file_global_stats {
    trace_record_counter_t n_compressed_typed_records;
    trace_record_counter_t n_uncompressed_typed_records;
    trace_record_counter_t n_metadata_records;
    unsigned compression_types_used;
    unsigned n_chunks;
};


struct trace_record_matcher_spec_s;     /* Defined in filter.h */

struct trace_parser;
typedef int (*trace_parser_event_handler_t)(struct trace_parser *parser, enum trace_parser_event_e event, void *event_data, void *arg);
typedef struct trace_parser {
    struct trace_file_info file_info;
    BufferParseContextList buffer_contexts;
    RecordsAccumulatorList records_accumulators;
    struct buffer_dump_context_s buffer_dump_context;
    trace_parser_event_handler_t event_handler;
    struct file_global_stats global_stats;
    trace_ts_t max_ts;
    void *arg;
    FILE *out_file;
    int color;
    int compact_traces;
    int show_timestamp;
    int always_hex;
    int indent;
    int nanoseconds_ts;
    bool_t wait_for_input;
    bool_t silent_mode;
    bool_t show_pid;
    int inotify_fd;
    int inotify_descriptor;
    enum trace_parser_param_name_disp_mode field_disp;
    int show_function_name;
    const struct trace_record_matcher_spec_s *record_filter;
    unsigned int ignored_records_count;
    enum trace_input_stream_type stream_type;
    bool_t free_dead_buffer_contexts;
    int after_count;
    unsigned records_rendered_count;
    const char* show_filename;
} trace_parser_t;

int TRACE_PARSER__from_file(trace_parser_t *parser, bool_t wait_for_input, const char *filename, trace_parser_event_handler_t event_handler, void *arg);
void TRACE_PARSER__fini(trace_parser_t *parser);
int TRACE_PARSER__dump_all_metadata(trace_parser_t *parser);
int TRACE_PARSER__dump(trace_parser_t *parser);
int TRACE_PARSER__dump_statistics(trace_parser_t *parser);

off64_t TRACE_PARSER__seek(trace_parser_t *parser, off64_t offset, int whence);

/* Create the hash for looking up type definitions */
struct trace_type_definition_mapped {
    const struct trace_type_definition* def;
    map_t map;
};

extern enum trace_severity trace_sev_mapping[];

#ifdef __cplusplus
}
#endif

#endif /* __TRACE_PARSER_H__ */
