/*
 * mm_writer.h
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

#ifndef MM_WRITER_H_
#define MM_WRITER_H_

#include <stdlib.h>
#include <sys/uio.h>
#include <pthread.h>

#include "../bool.h"
#include "trace_dumper.h"

struct trace_output_mmap_info {
    /* Fields writable only by the main thread */
    volatile trace_record_counter_t records_written;
    volatile bool_t writing_complete;
    pthread_t tid;
    size_t preferred_write_bytes;
    size_t page_size;

    /* Fields writable only by the worker thread (except initialization) */
    volatile trace_record_counter_t records_committed;
    volatile int lasterr;   /* Can also be written by the main thread if it detects unrecoverable data validation errors. */
    trace_ts_t next_flush_ts;

    /* Initialized by the main thread, deleted by the worker thread */
    struct trace_record *base;
    size_t mapping_len_bytes;
    int fd;
    const char *filename;
    const struct trace_dumper_configuration_s *global_conf;
 };

static inline bool_t trace_is_record_file_using_mm(const struct trace_record_file *record_file)
{
    return NULL != record_file->mapping_info;
}

void trace_mm_writer_update_written_record_count(struct trace_record_file *record_file);

int trace_dumper_prefetch_records_if_necessary(struct trace_output_mmap_info *mmap_info, size_t num_prefetch_records);

size_t num_records_pending(const struct trace_output_mmap_info *mmap_info);

int trace_dumper_write_via_mmapping(
        const struct trace_dumper_configuration_s *conf,
        struct trace_record_file *record_file,
        const struct iovec *iov,
        int iovcnt);

int trace_dumper_flush_mmapping(struct trace_record_file *record_file, bool_t synchronous);

#endif /* MM_WRITER_H_ */
