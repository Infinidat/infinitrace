/*
 * parser_internal.h
 *
 *  Created on: Dec 22, 2013
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

#ifndef PARSER_INTERNAL_H_
#define PARSER_INTERNAL_H_

#include "bool.h"
#include "trace_lib.h"
#include "parser.h"

static inline const struct trace_log_descriptor *get_log_descriptor(const struct trace_parser_buffer_context *context, size_t idx)
{
    return TRACE_REINTERPRET_CAST(const struct trace_log_descriptor *, TRACE_REINTERPRET_CAST(const char *, context->descriptors) + idx * context->metadata_log_desciptor_size);
}

#define AFTER_COUNT_COUNT 20

typedef struct {
    bool_t keep_going;
    trace_record_counter_t quota;
    int after_count_all;
    int after_count_cnt[AFTER_COUNT_COUNT];
    short unsigned int after_count_tid[AFTER_COUNT_COUNT];
} iter_t;

int process_next_record_from_file(trace_parser_t *parser, const struct trace_record_matcher_spec_s *filter,
                                         trace_parser_event_handler_t event_handler, void *arg, iter_t* iter)
                                         TRACE_PER_MODULE_SYMBOL;

#endif /* PARSER_INTERNAL_H_ */
