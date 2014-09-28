/*
 * filter.h
 *
 * Routines for creating and applying filters for finding trace records matching user-specified criteria.
 *
 *  Created on: Jan 9, 2013 by Yitzik Casapu, Infinidat
 *  Copyright by infinidat (http://infinidat.com)
 *  Author:     Josef Ezra, Infinidat
 *  Maintainer: Yitzik Casapu, Infinidat
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

#ifndef _TRACE_FILTER_H_
#define _TRACE_FILTER_H_

#ifndef __cplusplus
typedef struct trace_record_matcher_spec_s trace_record_matcher_spec_s;
#endif

enum trace_record_matcher_type {
    TRACE_MATCHER_TRUE,
    TRACE_MATCHER_FALSE,
    TRACE_MATCHER_OR,
    TRACE_MATCHER_AND,
    TRACE_MATCHER_NOT,
    TRACE_MATCHER_PID,
    TRACE_MATCHER_TID,
    TRACE_MATCHER_LOGID,
    TRACE_MATCHER_SEVERITY,
    TRACE_MATCHER_SEVERITY_LEVEL,
    TRACE_MATCHER_FUNCTION,
    TRACE_MATCHER_TYPE,
    TRACE_MATCHER_LOG_PARAM_VALUE,
    TRACE_MATCHER_LOG_NAMED_PARAM_VALUE,
    TRACE_MATCHER_PROCESS_NAME,
    TRACE_MATCHER_NESTING,
    TRACE_MATCHER_CONST_SUBSTRING,
    TRACE_MATCHER_CONST_STRCMP,
    TRACE_MATCHER_TIMERANGE,
    TRACE_MATCHER_QUOTA_MAX,
    TRACE_MATCHER_FUNCTION_NAME,
};

struct trace_record_matcher_spec_s {
    enum trace_record_matcher_type type;
    union trace_record_matcher_data_u {
        trace_pid_t pid;
        trace_pid_t tid;
        trace_log_id_t log_id;
        unsigned severity;
        struct trace_time_range {
            trace_ts_t start;
            trace_ts_t end;
        } time_range;

        char function_name[0x100];
        char type_name[0x100];
        char process_name[0x100];
        char const_string[0x100];
        /* unsigned long long param_value; */
        unsigned short nesting;
        trace_record_counter_t quota_max;

        struct trace_matcher_named_param_value {
            char param_name[0xf8];
            char compare_type;
            unsigned long long param_value;
        } named_param_value;

        struct trace_record_matcher_binary_operator_params {
            struct trace_record_matcher_spec_s *a, *b;
        } binary_operator_parameters;

        struct trace_record_matcher_unary_operator_params {
            struct trace_record_matcher_spec_s *param;
        } unary_operator_parameters;
    } u;
};

typedef struct trace_record_matcher_spec_s filter_t;

struct trace_filter_collection {

    filter_t * function;
    filter_t * grep;
    filter_t * strcmp;
    filter_t * value;
    filter_t * value2;
    filter_t * value3;
    filter_t * fuzzy;
    filter_t * time;
    filter_t * quota;
    filter_t * tid;
};


filter_t *trace_filter_create_chain(const struct trace_filter_collection *filters, unsigned severity);
bool_t trace_filter_init_from_cmdline(struct trace_filter_collection *filters, int option, const char *arg, void (*err_handler)(const char *msg));

/* Check whether any of the records inside a "chunk" can possibly match a filter */
struct trace_record;
bool_t trace_filter_match_record_chunk(
        const struct trace_record_matcher_spec_s *matcher,
        const struct trace_record *record,
        const char *proc_name);

/* Check whether an individual record matches a filter */
bool_t trace_filter_match_record(
        const struct trace_record_matcher_spec_s *matcher,
        const struct trace_parser_buffer_context *buffer,
        const struct trace_record *record,
        trace_record_counter_t *quota,
        bool_t *keep_going);

#endif /* _TRACE_FILTER_H_ */
