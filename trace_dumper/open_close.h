/*
 * open_close.h
 *
 *  Created on: Aug 9, 2012
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

#ifndef OPEN_CLOSE_H_
#define OPEN_CLOSE_H_

#include "../bool.h"
#include "trace_dumper.h"

int rotate_trace_file_if_necessary(struct trace_dumper_configuration_s *conf);
int open_trace_file_if_necessary(struct trace_dumper_configuration_s *conf);
bool_t trace_quota_is_enabled(const struct trace_dumper_configuration_s *conf);

bool_t is_closed(const struct trace_record_file *file);
int close_record_file(struct trace_dumper_configuration_s *conf);
int close_notification_file(struct trace_dumper_configuration_s *conf);
int close_async_write_fd(struct trace_record_file *file);
int close_all_files(struct trace_dumper_configuration_s *conf);

bool_t is_perf_logging_file_open(struct trace_record_file *record_file);

const char *trace_record_file_basename(const struct trace_record_file *record_file);

/* Functions for performing file operations be performed asynchronously. See enum trace_request_flags for the supported operations.
 * The handling of the requested operations word is thread safe. */

/* Request operations. Returns the value of the requested operation flags prior to the execution of the function. */
unsigned request_file_operations(struct trace_dumper_configuration_s *conf, unsigned op_flags);

/* Perform the operations corresponding to a logical AND of the requested operation flags and op_mask.
 * The mask may be used to only apply operations to files that the current thread owns.
 * Returns 0 if all the operation succeeded, -1 otherwise, and sets errno accordingly. */
int apply_requested_file_operations(struct trace_dumper_configuration_s *conf, unsigned op_mask);

#endif /* OPEN_CLOSE_H_ */
