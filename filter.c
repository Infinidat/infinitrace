/*
 * filter.c
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

#include "./platform.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <assert.h>

#include "bool.h"
#include "timeformat.h"
#include "trace_str_util.h"
#include "trace_defs.h"
#include "parser.h"
#include "filter.h"

static filter_t *new_filter_t() {
    filter_t* ret = calloc(1, sizeof(filter_t));
    return ret;
}

static void and_filter(filter_t *filter_a,
                       filter_t *filter_b) {

    filter_t * filter_dup_a = new_filter_t();
    memcpy(filter_dup_a, filter_a, sizeof(*filter_a));
    filter_a->type = TRACE_MATCHER_AND;
    filter_a->u.binary_operator_parameters.a = filter_dup_a;
    filter_a->u.binary_operator_parameters.b = filter_b;
}

static void or_filter(filter_t *filter_a,
                      filter_t *filter_b) {

    filter_t * filter_dup_a = new_filter_t();
    memcpy(filter_dup_a, filter_a, sizeof(*filter_a));
    filter_a->type = TRACE_MATCHER_OR;
    filter_a->u.binary_operator_parameters.a = filter_dup_a;
    filter_a->u.binary_operator_parameters.b = filter_b;
}


filter_t *trace_filter_create_chain(const struct trace_filter_collection *filters, unsigned severity)
{
    filter_t *filter = new_filter_t(); /* base */
    filter->type = TRACE_MATCHER_SEVERITY_LEVEL;
    filter->u.severity = severity;

#define WITH(FILTER) if (filters->FILTER) and_filter(filter, filters->FILTER)
    WITH(time);
    WITH(tid);
    WITH(grep);
    WITH(strcmp);
    WITH(value);
    WITH(value2);
    WITH(value3);
    WITH(fuzzy);
    WITH(function);
    WITH(quota);         /* must be last for lazy evaluation */
#undef  WITH

    return filter;
}

/* Copy a value to the const string field, return TRUE if the complete string fits, FALSE otherwise */
static bool_t set_const_string(filter_t * f, const char *s)
{
    return s[trace_strncpy_and_terminate(f->u.const_string, s, sizeof(f->u.const_string))] == '\0';
}

bool_t trace_filter_init_from_cmdline(struct trace_filter_collection *filters, int option, const char *arg, void (*err_handler)(const char *msg))
{
#define QUIT_ON_ERR(msg) { err_handler(msg); return FALSE; }

    long long num = -1;

    switch (option) {
    case 'Q':
        {
            if (!trace_get_number(arg, &num) || (num < 0))
                QUIT_ON_ERR(" -Q [val] : [val] must be a valid positive number");

            filters->quota = new_filter_t();
            filters->quota->type = TRACE_MATCHER_QUOTA_MAX;
            filters->quota->u.quota_max = num;
        }
        break;

    case 't':
        {
            unsigned long long nanosec = str_to_nano_seconds(arg);
            if (filters->time == NULL) {
                filters->time = new_filter_t();
                filters->time->type = TRACE_MATCHER_TIMERANGE;
                filters->time->u.time_range.start = nanosec;
                filters->time->u.time_range.end   = LLONG_MAX;
            }
            else if (nanosec < filters->time->u.time_range.start) {
                filters->time->u.time_range.end = filters->time->u.time_range.start;
                filters->time->u.time_range.start = nanosec;
            }
            else
                filters->time->u.time_range.end   = nanosec;
        }
        break;

#define WITH(FILTER) if (filters->FILTER == NULL) filters->FILTER = f; else or_filter(filters->FILTER, f)
    case 'g':
        {
            filter_t * f = new_filter_t();
            f->type = TRACE_MATCHER_CONST_SUBSTRING;
            set_const_string(f, arg);
            WITH(grep);
        }
        break;

    case 'c':
        {
            filter_t * f = new_filter_t();
            f->type = TRACE_MATCHER_CONST_STRCMP;
            set_const_string(f, arg);
            WITH(strcmp);
        } break;

    case 'w':
    case 'v':
    case 'u':
        {
            filter_t * f = new_filter_t();
            char* equal = NULL ;
    #define OR_MAYBE(C) if (! equal ) equal = strrchr(arg, C)
            OR_MAYBE('=');
            OR_MAYBE('>');
            OR_MAYBE('<');
    #undef  OR_MAYBE
            if (equal) {
                if (equal > sizeof(f->u.named_param_value.param_name) + arg - 1) {
                    fprintf(stderr, "'%s': Too long.", arg);
                    return FALSE;
                }

                if (!trace_get_number(equal+1, &num))
                    QUIT_ON_ERR(" Bad integer number in named value");
                f->type = TRACE_MATCHER_LOG_NAMED_PARAM_VALUE;
                f->u.named_param_value.compare_type = *equal;
                strncpy(f->u.named_param_value.param_name, arg, equal-arg);
            }
            else {
                if (!trace_get_number(arg, &num))
                    QUIT_ON_ERR(" Bad integer number in named value");
                f->type = TRACE_MATCHER_LOG_PARAM_VALUE;
                f->u.named_param_value.compare_type = '=';
            }

            f->u.named_param_value.param_value = num;

            switch(option) {
            case 'v':
                WITH(value);
                break;

            case 'u':
                WITH(value2);
                break;

            case 'w':
                WITH(value3);
                break;

            default:
                assert(0);
                break;
            }
        }
        break;
    case 'z':
        {
            filter_t * f = new_filter_t();
            if (trace_get_number(arg, &num)) {
                f->type = TRACE_MATCHER_LOG_PARAM_VALUE;
                f->u.named_param_value.param_value = num;
                f->u.named_param_value.compare_type = '=';
            }
            else {
                f->type = TRACE_MATCHER_CONST_SUBSTRING;
                set_const_string(f, arg);
            }
            WITH(fuzzy);
        }
        break;
    case 'f':
        {
            filter_t * f = new_filter_t();
            f->type = TRACE_MATCHER_FUNCTION_NAME;
            strncpy(f->u.function_name, arg, sizeof(f->u.function_name));
            WITH(function);
        }
        break;
    case 'd':
        {
            filter_t * f = new_filter_t();
            f->type = TRACE_MATCHER_TID;
            if (!trace_get_number(arg, &num))
                QUIT_ON_ERR(" Bad integer number in tid");

            f->u.tid = num;
            WITH(tid);
        }
        break;

#undef WITH

    default:
        return FALSE;
    }

    return TRUE;
}

bool_t trace_filter_match_record_chunk(
        const struct trace_record_matcher_spec_s *matcher,
        const struct trace_record *record,
        const char *proc_name)
{
    if (NULL == matcher) {  /* No filter - anything matches */
        return TRUE;
    }

    const struct trace_record_buffer_dump *buffer_dump = &record->u.buffer_chunk;

    switch ((int) matcher->type) {
        case TRACE_MATCHER_TRUE:
            return TRUE;

        case TRACE_MATCHER_FALSE:
            return FALSE;

        case TRACE_MATCHER_NOT:
            return !trace_filter_match_record_chunk(matcher->u.unary_operator_parameters.param, record, proc_name);

        case TRACE_MATCHER_OR:
            return (trace_filter_match_record_chunk(matcher->u.binary_operator_parameters.a, record, proc_name) ||
                    trace_filter_match_record_chunk(matcher->u.binary_operator_parameters.b, record, proc_name));

        case TRACE_MATCHER_AND:
            return (trace_filter_match_record_chunk(matcher->u.binary_operator_parameters.a, record, proc_name) &&
                    trace_filter_match_record_chunk(matcher->u.binary_operator_parameters.b, record, proc_name));

            /*
        case TRACE_MATCHER_TIMERANGE:
            return (buffer_dump->ts > matcher->u.time_range.start);
            */

        case TRACE_MATCHER_PID:
            return record->pid == matcher->u.pid;

        case TRACE_MATCHER_SEVERITY:
            return (buffer_dump->severity_type) & (1 << matcher->u.severity);

        case TRACE_MATCHER_SEVERITY_LEVEL:
            return (buffer_dump->severity_type) >= (matcher->u.severity);

        case TRACE_MATCHER_PROCESS_NAME:
            return (proc_name && strcmp(matcher->u.process_name, proc_name) == 0);

        default:
            return TRUE;
    }
    return TRUE;
}


static bool_t record_params_contain_string(
        const struct trace_parser_buffer_context *buffer,
        const struct trace_record_typed *typed_record,
        const char *const_str,
        int exact,
        unsigned int *log_size) {

    unsigned int metadata_index = typed_record->log_id;
    if (metadata_index >= buffer->metadata->log_descriptor_count)
        return FALSE;

    const struct trace_log_descriptor *log_desc = get_log_descriptor(buffer, metadata_index);;
    const struct trace_param_descriptor *param = log_desc->params;
    const unsigned char *pdata = typed_record->payload;
    for (; param->flags != 0; param++) {

        switch(param->flags &
               (TRACE_PARAM_FLAG_ENUM    |
                TRACE_PARAM_FLAG_NUM_8   |
                TRACE_PARAM_FLAG_NUM_16  |
                TRACE_PARAM_FLAG_NUM_32  |
                TRACE_PARAM_FLAG_NUM_64  |
                TRACE_PARAM_FLAG_CSTR    |
                TRACE_PARAM_FLAG_VARRAY  |
                TRACE_PARAM_FLAG_NESTED_LOG)) {

        case TRACE_PARAM_FLAG_ENUM: {
            pdata += sizeof(unsigned int);
        } break;

        case TRACE_PARAM_FLAG_NUM_8: {
            pdata += sizeof(char);
        } break;

        case TRACE_PARAM_FLAG_NUM_16: {
            pdata += sizeof(unsigned short);
        } break;

        case TRACE_PARAM_FLAG_NUM_32: {
            pdata += sizeof(unsigned int);
        } break;

        case TRACE_PARAM_FLAG_NUM_64: {
            pdata += sizeof(unsigned long long);
        } break;

        case TRACE_PARAM_FLAG_CSTR: {
            if (exact ?
                strcmp(param->const_str, const_str) == 0 :
                strstr(param->const_str, const_str) != 0)
                return TRUE;
        } break;

        case TRACE_PARAM_FLAG_VARRAY: {
            while (1) {
                unsigned char sl = (*(unsigned char *)pdata);
                unsigned char len = sl & 0x7f;
                unsigned char continuation = sl & 0x80;

                pdata += sizeof(len) + len;
                if (!continuation) {
                    break;
                }
            }
        } break;

        case TRACE_PARAM_FLAG_NESTED_LOG: {
            unsigned int _log_size = 0;
            if (record_params_contain_string(buffer, (struct trace_record_typed *) pdata, const_str, exact, &_log_size))
                return TRUE;
            pdata += _log_size;
        } break;

        default:
            continue;
        }
    }

    if ( log_size )
        *log_size = (char *) pdata - (char *) typed_record;
    return FALSE;
}


static bool_t record_params_contain_value(
        const struct trace_parser_buffer_context *buffer,
        const struct trace_record_typed *typed_record,
        char compare_type,
        unsigned long long value,
        const char *param_name,
        unsigned int *log_size)
{
    unsigned int metadata_index = typed_record->log_id;
    if (metadata_index >= buffer->metadata->log_descriptor_count)
        return FALSE;

    const struct trace_log_descriptor *log_desc = get_log_descriptor(buffer, metadata_index);;
    const struct trace_param_descriptor *param = log_desc->params;

    const unsigned char *pdata = typed_record->payload;
    unsigned long long param_value = 0;
    for (; param->flags != 0; param++) {
        unsigned long long value_mask = 0;

        switch(param->flags &
               (TRACE_PARAM_FLAG_ENUM    |
                TRACE_PARAM_FLAG_NUM_8   |
                TRACE_PARAM_FLAG_NUM_16  |
                TRACE_PARAM_FLAG_NUM_32  |
                TRACE_PARAM_FLAG_NUM_64  |
                TRACE_PARAM_FLAG_VARRAY  |
                TRACE_PARAM_FLAG_NESTED_LOG)) {

        case TRACE_PARAM_FLAG_ENUM: {
            value_mask = ULLONG_MAX;
            param_value = (unsigned long long) (*(unsigned int *)(pdata));
            pdata += sizeof(unsigned int);
        } break;

        case TRACE_PARAM_FLAG_NUM_8: {
            value_mask = 0xff;
            param_value = (unsigned long long) (*(unsigned char *)(pdata));
            pdata += sizeof(char);
        } break;

        case TRACE_PARAM_FLAG_NUM_16: {
            value_mask = 0xffff;
            param_value = (unsigned long long) (*(unsigned short *)(pdata));
            pdata += sizeof(unsigned short);
        } break;

        case TRACE_PARAM_FLAG_NUM_32: {
            value_mask = 0xffffffff;
            param_value = (unsigned long long) (*(unsigned int *)(pdata));
            pdata += sizeof(unsigned int);
        } break;

        case TRACE_PARAM_FLAG_NUM_64: {
            value_mask = ULLONG_MAX;
            param_value = *((unsigned long long *) (pdata));
            pdata += sizeof(unsigned long long);
        } break;

        case TRACE_PARAM_FLAG_VARRAY: {
            while (1) {
                unsigned char sl = (*(unsigned char *)pdata);
                unsigned char len = sl & 0x7f;
                unsigned char continuation = sl & 0x80;

                pdata += sizeof(len) + len;
                if (!continuation) {
                    break;
                }
            }
        } break;

        case TRACE_PARAM_FLAG_NESTED_LOG: {
            unsigned int _log_size = 0;
            if (record_params_contain_value(buffer, (struct trace_record_typed *) pdata, compare_type, value, param_name, &_log_size))
                return TRUE;
            pdata += _log_size;
        } break;

        default:
            continue;
        }

        if ( (value_mask)
             &&

             ((param_name == NULL) ||
              (param->param_name &&
               strcmp(param_name, param->param_name) == 0))

             &&

             (compare_type == '>' ?
              (value_mask&value) < param_value :
              compare_type == '<' ?
              (value_mask&value) > param_value :
              (value_mask&value) == param_value
             )
             )
            return TRUE;
    }

    if ( log_size )
        *log_size = (char *) pdata - (char *) typed_record;
    return FALSE;
}



static bool_t params_have_type_name(const struct trace_param_descriptor *param, const char *type_name)
{
    for (; param->flags != 0; param++) {
        if (!(param->flags & (TRACE_PARAM_FLAG_CSTR)) && param->type_name) {
            if (strcmp(param->type_name, type_name) == 0) {
                return TRUE;
            }
        }
    }

    return FALSE;
}


bool_t trace_filter_match_record(
        const struct trace_record_matcher_spec_s *matcher,
        const struct trace_parser_buffer_context *buffer,
        const struct trace_record *record,
        long long *quota,
        bool_t *keep_going)
{
    if (NULL == matcher) { /* No filter - anything matches */
        return TRUE;
    }

    const unsigned int metadata_index = record->u.typed.log_id;
    if (metadata_index >= buffer->metadata->log_descriptor_count)
        return FALSE;

    const struct trace_log_descriptor *log_desc = get_log_descriptor(buffer, metadata_index);

    switch (matcher->type) {
    case TRACE_MATCHER_TRUE:
        return TRUE;

    case TRACE_MATCHER_FALSE:
        return FALSE;

    case TRACE_MATCHER_NOT:
        return !trace_filter_match_record(matcher->u.unary_operator_parameters.param, buffer, record, quota, keep_going);

    case TRACE_MATCHER_OR:
        return (trace_filter_match_record(matcher->u.binary_operator_parameters.a, buffer, record, quota, keep_going) ||
                trace_filter_match_record(matcher->u.binary_operator_parameters.b, buffer, record, quota, keep_going));

    case TRACE_MATCHER_AND:
        return (trace_filter_match_record(matcher->u.binary_operator_parameters.a, buffer, record, quota, keep_going) &&
                trace_filter_match_record(matcher->u.binary_operator_parameters.b, buffer, record, quota, keep_going));

    case TRACE_MATCHER_PID:
        return record->pid == matcher->u.pid;

    case TRACE_MATCHER_NESTING:
        return record->nesting == matcher->u.nesting;

    case TRACE_MATCHER_TID:
        return record->tid == matcher->u.tid;

    case TRACE_MATCHER_LOGID:
        return record->u.typed.log_id == matcher->u.log_id;

    case TRACE_MATCHER_SEVERITY:
        return record->severity == matcher->u.severity;

    case TRACE_MATCHER_SEVERITY_LEVEL:
        return record->severity >= matcher->u.severity;

    case TRACE_MATCHER_TYPE:
        return params_have_type_name(log_desc->params, matcher->u.type_name);

    case TRACE_MATCHER_FUNCTION:
        if ((log_desc->kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY) ||
            (log_desc->kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_LEAVE)) {
            if (strcmp(log_desc->params->const_str, matcher->u.function_name) == 0) {
                return TRUE;
            } else {
                return FALSE;
            }
        }
        break;

    case TRACE_MATCHER_LOG_PARAM_VALUE:
        return record_params_contain_value(buffer, &record->u.typed,
                                           matcher->u.named_param_value.compare_type,
                                           matcher->u.named_param_value.param_value,
                                           NULL, NULL);

    case TRACE_MATCHER_LOG_NAMED_PARAM_VALUE:
        return record_params_contain_value(buffer, &record->u.typed,
                                           matcher->u.named_param_value.compare_type,
                                           matcher->u.named_param_value.param_value,
                                           matcher->u.named_param_value.param_name,
                                           NULL);

    case TRACE_MATCHER_CONST_SUBSTRING:
        return record_params_contain_string(buffer, &record->u.typed, matcher->u.const_string, 0, NULL);

    case TRACE_MATCHER_CONST_STRCMP:
        return record_params_contain_string(buffer, &record->u.typed, matcher->u.const_string, 1, NULL);

    case TRACE_MATCHER_TIMERANGE:
        return ( (record->ts <= matcher->u.time_range.end ) ?
                 (record->ts >= matcher->u.time_range.start) :
                 keep_going ? (*keep_going = FALSE) : FALSE );

    case TRACE_MATCHER_PROCESS_NAME:
        return (0 == strcmp(matcher->u.process_name, buffer->name));

    case TRACE_MATCHER_QUOTA_MAX:
        if(!quota) return TRUE;  /* weird */
        if (*quota == 0)
            *quota = matcher->u.quota_max + 1;
        return ((0 < --(*quota)) ?
                TRUE :
                (*keep_going = FALSE));

    case TRACE_MATCHER_FUNCTION_NAME:
        return (log_desc->function &&
                // log_desc->function[0] &&
                0 == strcmp(log_desc->function, matcher->u.function_name));

    default:
        return FALSE;

    }

    return FALSE;
}
