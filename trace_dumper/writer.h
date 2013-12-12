/*
 * writer.h
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

#ifndef WRITER_H_
#define WRITER_H_

#include <sys/uio.h>
#include <pthread.h>
#include "../bool.h"
#include "trace_dumper.h"


int write_single_record(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, const struct trace_record *rec);

/* Write to the output file using a mechanism selected according to conf->low_latency_write, and optionally dump traces to the parser. */
int trace_dumper_write(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, const struct iovec *iov, int iovcnt);

/* A wrapper for trace_dumper_write which syncs the written data to the disk after the write. */
int trace_dumper_write_to_record_file(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file);

/* If the existing size of the IO vector is insufficient to hold size_t records, increase it by at least 50% */
struct iovec *increase_iov_if_necessary(struct trace_record_file *record_file, size_t required_size);

/* Lower level trace writing functions that use specific mechanisms */
int trace_dumper_write_via_file_io(const struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, const struct iovec *iov, int iovcnt);

void trace_dumper_update_written_record_count(struct trace_record_file *record_file);
bool_t trace_dumper_record_file_state_is_ok(const struct trace_record_file *record_file);

#endif /* WRITER_H_ */
