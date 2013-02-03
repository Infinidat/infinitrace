/*
 * write_prep.h: Routines used to prepare I/O vectors for writing
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

#ifndef WRITE_PREP_H_
#define WRITE_PREP_H_

#include <sys/uio.h> /* For struct iovec */

struct records_pending_write {
    unsigned total;
    unsigned up_to_buf_end;
    unsigned from_buf_start;
    unsigned beyond_chunk_size;
    long lost;
    long remaining_before_loss;
};

/* Find which trace records have been added to the given mapped records since last time we flushed them.
 * The result is stored in delta. */
void calculate_delta(
        const struct trace_mapped_records *mapped_records,
        struct records_pending_write *delta);

/* Initialize dump and chunk header records */

void init_dump_header(struct trace_dumper_configuration_s *conf, struct trace_record *dump_header_rec,
                             unsigned long long cur_ts,
                             struct iovec **iovec, unsigned int *num_iovecs, unsigned int *total_written_records);

/* Initialize the buffer chunk header and set-up the iovec for the no wrap-around case. */
void init_buffer_chunk_record(struct trace_dumper_configuration_s *conf, const struct trace_mapped_buffer *mapped_buffer,
                                     struct trace_mapped_records *mapped_records, struct trace_record_buffer_dump **bd,
                                     struct iovec **iovec, unsigned int *iovcnt,
                                     const struct records_pending_write *deltas,
                                     unsigned long long cur_ts, unsigned int total_written_records);

/* Scan the given mapped records for trace records whose severity exceeds threshold_severity and create an IO vector for writing them to the
 * notification file */
unsigned add_warn_records_to_iov(
        const struct trace_mapped_records *mapped_records,
        unsigned count,
        enum trace_severity threshold_severity,
        struct trace_record_file *record_file);

/* Wrapper function that gets the monotonic time-stamp with error reporting if necessary */
trace_ts_t get_nsec_monotonic(void);

#endif /* WRITE_PREP_H_ */
