/***
Copyright 2012 Yotam Rubin <yotamrubin@gmail.com>
   Sponsored by infinidat (http://infinidat.com)

   Modified and maintained by Yitzik Casapu of Infinidat - 2012

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

#ifndef TRACE_DUMPER_H_
#define TRACE_DUMPER_H_

#include <sys/uio.h>

#include "../bool.h"
#include "../trace_metadata_util.h"
#include "../trace_parser.h"
#include "../min_max.h"
#include "../bool.h"
#include "../array_length.h"


#define COLOR_BOOL conf->color
#include "../colors.h"
#define MAX_FILTER_SIZE (10)
#define METADATA_IOVEC_SIZE 2*(MAX_METADATA_SIZE/TRACE_RECORD_PAYLOAD_SIZE+1)
#define MAX_FILTER_SIZE (10)
#define METADATA_IOVEC_SIZE 2*(MAX_METADATA_SIZE/TRACE_RECORD_PAYLOAD_SIZE+1)

// The threshold stands at about 60 MBps
#define OVERWRITE_THRESHOLD_PER_SECOND (1000000)
#define TRACE_SECOND (1000000000ULL)
#define RELAXATION_BACKOFF (TRACE_SECOND * 10)

struct trace_mapped_metadata {
    struct iovec metadata_iovec[METADATA_IOVEC_SIZE];
    struct trace_record metadata_payload_record;
    unsigned long log_descriptor_count;
    unsigned long type_definition_count;
    unsigned int size;
    void *base_address;
    int  metadata_fd;
    struct trace_log_descriptor *descriptors;
};

struct trace_mapped_records {
    volatile struct trace_record *records;
    volatile struct trace_records_mutable_metadata *mutab;
    struct trace_records_immutable_metadata *imutab;

    unsigned long long current_read_record;
    unsigned int last_flush_offset;

    unsigned long long next_flush_ts;
    unsigned int next_flush_record;
    unsigned int next_flush_offset;
	unsigned int old_generation;

    struct trace_record buffer_dump_record;
};

#define TRACE_BUFNAME_LEN (0x100)
#define MAX_BUFFER_COUNT (10)

struct trace_mapped_buffer {
    char name[TRACE_BUFNAME_LEN];
    void *records_buffer_base_address;
    int  record_buffer_fd;
    unsigned long records_buffer_size;
    unsigned long last_metadata_offset;
    bool_t metadata_dumped;
    struct trace_mapped_records mapped_records[TRACE_BUFFER_NUM_RECORDS];
    struct trace_mapped_metadata metadata;
    trace_pid_t pid;
    bool_t dead;
    trace_ts_t process_time;
};


#define TRACE_FILE_PREFIX "trace."

#define TRACE_METADATA_IOVEC_SIZE  (2*(MAX_METADATA_SIZE/TRACE_RECORD_PAYLOAD_SIZE+1))

#define TRACE_PREFERRED_FILE_MAX_RECORDS_PER_FILE        0x1000000
#define PREFERRED_NUMBER_OF_TRACE_HISTORY_FILES (7)
#define TRACE_PREFERRED_MAX_RECORDS_PER_LOGDIR        (TRACE_PREFERRED_FILE_MAX_RECORDS_PER_FILE) * PREFERRED_NUMBER_OF_TRACE_HISTORY_FILES;
#define TRACE_FILE_MAX_RECORDS_PER_CHUNK       0x10000
#define TRACE_FILE_IMMEDIATE_FLUSH_THRESHOLD	(TRACE_FILE_MAX_RECORDS_PER_CHUNK / 2)

struct trace_record_file {
    unsigned long records_written;
    char filename[0x100];
    int fd;
};

enum operation_type {
    OPERATION_TYPE_DUMP_RECORDS,
    OPERATION_TYPE_DUMP_BUFFER_STATS,
};


CREATE_LIST_PROTOTYPE(MappedBuffers, struct trace_mapped_buffer, 100);
/* Note: The number of mapped buffers sets an upper limit to the number of processes from which we can simultaneously collect traces. */

typedef char buffer_name_t[0x100];
CREATE_LIST_PROTOTYPE(BufferFilter, buffer_name_t, 20);

CREATE_LIST_PROTOTYPE(PidList, trace_pid_t, MappedBuffers_NUM_ELEMENTS);


struct trace_dumper_configuration_s {
    const char *logs_base;
    const char *attach_to_pid;
    int should_quit;
    struct trace_record_matcher_spec_s severity_filter[SEVERITY_FILTER_LEN];
    unsigned int header_written;
    unsigned int write_to_file;
    unsigned int dump_online_statistics;
    const char *fixed_output_filename;
    unsigned int online;
    unsigned int trace_online;
    unsigned int debug_online;
    unsigned int info_online;
    unsigned int warn_online;
    unsigned int error_online;
    unsigned int syslog;
    unsigned long long start_time;
    unsigned int no_color_specified;
    unsigned int color;
    enum trace_severity minimal_allowed_severity;
    unsigned long long next_possible_overwrite_relaxation;
    unsigned long long last_overwrite_test_time;
    unsigned long long last_overwrite_test_record_count;

    const char *quota_specification;
    long long max_records_per_logdir;
    unsigned long long max_records_per_file;
    unsigned long long max_records_per_second;
    int stopping;
	struct trace_record_file record_file;
	unsigned int last_flush_offset;
    enum operation_type op_type;
    trace_ts_t prev_flush_ts;
    trace_ts_t next_flush_ts;
    trace_ts_t ts_flush_delta;
    trace_ts_t next_stats_dump_ts;
    trace_ts_t next_housekeeping_ts;
    struct trace_parser parser;
    BufferFilter filtered_buffers;
    MappedBuffers mapped_buffers;
    PidList dead_pids;
    struct iovec flush_iovec[1 + (3 * MAX_BUFFER_COUNT * TRACE_RECORD_BUFFER_RECS)];
    unsigned int flush_iovec_total_records;
};


#endif /* TRACE_DUMPER_H_ */
