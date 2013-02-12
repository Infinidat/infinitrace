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

#define _GNU_SOURCE

#include "platform.h"

#include <sys/types.h>
#ifdef _USE_INOTIFY_
#include <sys/inotify.h>
#endif

#include <fcntl.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <sys/poll.h>
#include <assert.h>
#include <stdarg.h>
#include <sysexits.h>

#include "parser.h"
#include "min_max.h"
#include "array_length.h"
#include "trace_defs.h"
#include "list_template.h"
#include "trace_metadata_util.h"
#include "object_pool.h"
#include "trace_sev_display.h"
#include "string.h"
#include "timeformat.h"
#include "trace_str_util.h"
#include "filter.h"
#include "parser_mmap.h"

/* print out */
typedef struct {
    char buf[0x4000];
    unsigned int i;
} out_fd;

static void out_init(out_fd* out) {
    out->i = 0;
}
static void out_flush(out_fd* out) {
#define _outout stdout
    fwrite(out->buf, 1, out->i, _outout);
    out->i = 0;
#undef _outout
}
static void out_check(out_fd* out) {
    if (out->i < sizeof(out->buf) - 0x200)
        return;
    fprintf(stderr, "Formatted record is too long (0x%x)", out->i);
    out_flush(out);
    /* exit(EX_DATAERR); */
}
static void SAY_S(out_fd* out, const char* str) {
    out_check(out);
    int capacity = sizeof(out->buf) - out->i;
    char* dst = out->buf + out->i;
    out->i += trace_strncpy(dst, str, capacity);
}
static inline void SAY_C(out_fd* out, const char chr) {
    out->buf[out->i++] = chr;
}
static void SAY_F(out_fd* out, const char* fmt, ...) {
    out_check(out);
    va_list args;
    va_start(args, fmt);
    out->i += vsprintf(out->buf + out->i, fmt, args);
    va_end  (args);
} 

#define SAY_COL(O,C) do { if (color_bool) { SAY_S(O,C); } } while (0)
#define SAY_COLORED(O,S,C) do { if (color_bool) { SAY_COL(O,C); SAY_S(O,S); SAY_COL(O,ANSI_RESET);} else { SAY_S(O,S); } } while(0)

static inline void SAY_ESCAPED_C(out_fd* out, char chr) {
	static const char hex_digits[] = "0123456789abcdef";

	if (isprint(chr)) {
		SAY_C(out, chr);
	}
	else {
		SAY_C(out, '\\');
		switch (chr) {
		case '\n': SAY_C(out, 'n'); break;
		case '\t': SAY_C(out, 't'); break;
		case '\r': SAY_C(out, 'r'); break;
		case '\0': SAY_C(out, '0'); break;
		default:
			SAY_C(out, 'x');
			SAY_C(out, hex_digits[(chr >> 4) & 0xf]);
			SAY_C(out, hex_digits[ chr       & 0xf]);
			break;
		}
	}
}

static void SAY_ESCAPED_S(out_fd* out, const char* buf, size_t size) {
    out_check(out);
    for (size_t i = 0; i < size; i++) {
    	SAY_ESCAPED_C(out, buf[i]);
    }
}

static void SAY_INT(out_fd* out, bool_t color_bool, bool_t force_hex, unsigned flags, unsigned value) {
    SAY_COL(out, CYAN_B);
    const bool_t hex = force_hex || (flags & TRACE_PARAM_FLAG_HEX);
    SAY_F  (out, hex ? "0x%x" : (flags & TRACE_PARAM_FLAG_UNSIGNED) ? "%u" : "%d", value);
    SAY_COL(out, ANSI_RESET);
}

static int ends_with_equal(const out_fd* out) {
    return (out->i > 1 && out->buf[out->i-1] == '=');
}


CREATE_LIST_IMPLEMENTATION(BufferParseContextList, struct trace_parser_buffer_context)
CREATE_LIST_IMPLEMENTATION(RecordsAccumulatorList, struct trace_record_accumulator)

static enum trace_severity trace_sev_mapping[TRACE_SEV__COUNT];

/*
 * return value:
 *    1: new data
 *    0: timeout
 *   -1: error
 *
 */
static int wait_for_data(trace_parser_t *parser, int ms_timeout __attribute__((unused)))
{
	if (parser->inotify_fd < 0) {
		sleep(1);
		return 1;
	}

#ifdef _USE_INOTIFY_
    struct inotify_event event;
    struct pollfd pollfd;

    pollfd.fd = parser->inotify_fd;

    while (TRUE) {
        pollfd.events = POLLIN;
        pollfd.revents = 0;

        int rc = poll(&pollfd, 1, ms_timeout);
        if (-1 == rc) {
            if (errno == EINTR)
                continue;
            else
                return -1;
        }
        if (0 == rc) {
            return 0;
        }

        rc = read(parser->inotify_fd, &event, sizeof(event));
        if (rc != sizeof(event)) {
            return -1;
        }

        if (event.mask & IN_MODIFY) {
            return 1;
        }
    }
#else
    assert(0);
    return -1;
#endif
}

static int adjust_offset_for_added_data(trace_parser_t *parser)
{
	int rc = wait_for_data(parser, -1);
	if ((rc > 0) && (trace_parser_update_end_offset(parser) < (off64_t) 0)) {
		return -1;
	}

	return rc;
}

static void wait_and_inform_user(void)
{
	static bool_t printed_wait_msg = FALSE;
	if (! printed_wait_msg) {
		fputs("Waiting for data ...", stderr);
		printed_wait_msg = TRUE;
	}
	sleep(1);
	fputc('.', stderr);
}

static inline bool_t record_has_null_header(const struct trace_record *rec)
{
	return 0 == *(__uint128_t *)rec;
}

static int read_next_record(trace_parser_t *parser, struct trace_record *record)
{
    while (TRUE) {
        if (parser->file_info.current_offset < parser->file_info.end_offset) {
        	const struct trace_record *const src_rec = (const struct trace_record *) ((unsigned char *) parser->file_info.file_base + (parser->file_info.current_offset));
        	if (parser->wait_for_input && record_has_null_header(src_rec)) {
        		wait_and_inform_user();
        		continue;
        	}

            memcpy(record, src_rec, sizeof(*record));
            parser->file_info.current_offset += sizeof(*record);
            return 0;
        }

        if (parser->wait_for_input) {
            parser->silent_mode = FALSE;
            if (adjust_offset_for_added_data(parser) < 0) {
            	return -1;
            }
        } else {
            memset(record, 0, sizeof(*record));
            parser->buffer_dump_context.file_offset++;
            record->rec_type = TRACE_REC_TYPE_END_OF_FILE;
            record->ts = 0;
            return 0;
        }
    }
}


void trace_parser_init(trace_parser_t *parser, trace_parser_event_handler_t event_handler, void *arg, enum trace_input_stream_type stream_type)
{
	/* Catch resource deallocation issues. This is only guaranteed to work if a single parser structure is used consistently. */
	static trace_parser_t *last_parser_used = NULL;
	bool_t first_init = (parser != last_parser_used);
	assert((MAP_FAILED == parser->file_info.file_base) || first_init);
	assert((-1 == parser->file_info.fd) || first_init);

    memset(parser, 0, sizeof(*parser));
    parser->event_handler = event_handler;
    parser->arg = arg;
    parser->stream_type = stream_type;
    BufferParseContextList__init(&parser->buffer_contexts);
    parser->show_timestamp = TRUE;
    parser->show_function_name = TRUE;
    parser->file_info.file_base = MAP_FAILED;
    parser->file_info.fd = -1;
    parser->inotify_fd = -1;
    parser->inotify_descriptor = -1;
    RecordsAccumulatorList__init(&parser->records_accumulators);

    last_parser_used = parser;
}

static int read_file_header(trace_parser_t *parser, struct trace_record *record) {
    int rc = read_next_record(parser, record);
    if (0 != rc) {
        return -1;
    }

    if (record->rec_type != TRACE_REC_TYPE_FILE_HEADER) {
        errno = EINVAL;
        return -1;
    }

    return 0;
}

static struct trace_parser_buffer_context *get_buffer_context_by_pid(trace_parser_t *parser, unsigned short pid)
{
    int i;
    struct trace_parser_buffer_context *context;
    for (i = 0; i < BufferParseContextList__element_count(&parser->buffer_contexts); i++) {
        BufferParseContextList__get_element_ptr(&parser->buffer_contexts, i, &context);
        if (context->id == pid) {
            return context;
        }
    }

    return NULL;
}

static int TRACE_PARSER__free_buffer_context_by_pid(trace_parser_t *parser, unsigned short pid)
{
    int i;
    struct trace_parser_buffer_context *context;
    for (i = 0; i < BufferParseContextList__element_count(&parser->buffer_contexts); i++) {
        BufferParseContextList__get_element_ptr(&parser->buffer_contexts, i, &context);
        if (context->id == pid) {
            free(context->metadata);
            BufferParseContextList__remove_element(&parser->buffer_contexts, i);
            return 0;
        }
    }

    errno = ESRCH;
    return -1;
}

static void free_all_metadata(trace_parser_t *parser)
{
    int i;
    for (i = 0; i < BufferParseContextList__element_count(&parser->buffer_contexts); i++) {
    	struct trace_parser_buffer_context *ptr = NULL;
        if (BufferParseContextList__get_element_ptr(&parser->buffer_contexts, i, &ptr) < 0) {
        	continue;
        }

        if ((NULL != ptr) && (NULL != ptr->metadata)) {
        	free(ptr->metadata);
        	ptr->metadata = NULL;
        }
    }
}

static int metadata_info_started(trace_parser_t *parser, const struct trace_record *rec)
{
    struct trace_parser_buffer_context *context = get_buffer_context_by_pid(parser, rec->pid);

    if (context) {
        TRACE_PARSER__free_buffer_context_by_pid(parser, rec->pid);
    }

    if ((parser->file_info.format_version >= TRACE_FORMAT_VERSION_INTRODUCED_DEAD_PID_LIST) &&
    	(parser->free_dead_buffer_contexts) &&
        (TRACE_MAGIC_METADATA == rec->u.metadata.metadata_magic))    {
    	size_t i;
    	for (i = 0; i < ARRAY_LENGTH(rec->u.metadata.dead_pids); i++) {
    		trace_pid_t pid = rec->u.metadata.dead_pids[i];
    		if (pid > 0) {
    			TRACE_PARSER__free_buffer_context_by_pid(parser, pid);
    		}
    	}
    }

    struct trace_parser_buffer_context new_context;
    new_context.id = rec->pid;
    new_context.metadata_size = rec->u.metadata.metadata_size_bytes;
    if (new_context.metadata_size > MAX_METADATA_SIZE) {
    	errno = EINVAL;
        return -1;
    }

    new_context.metadata = malloc(new_context.metadata_size);
    if (NULL == new_context.metadata) {
        return -1;
    }

    new_context.current_metadata_offset = 0;
    if (BufferParseContextList__add_element(&parser->buffer_contexts, &new_context) < 0) {
    	free(new_context.metadata);
    	new_context.metadata = NULL;
    	return -1;
    }

    return 0;
}

static int append_metadata(struct trace_parser_buffer_context *context, const struct trace_record *rec)
{
    unsigned int remaining = context->metadata_size - context->current_metadata_offset;
    if (remaining == 0) {
    	errno = EINVAL;
        return -1;
    }
    memcpy(((char *)context->metadata) + context->current_metadata_offset, rec->u.payload, MIN(remaining, TRACE_RECORD_PAYLOAD_SIZE));
    context->current_metadata_offset += MIN(remaining, TRACE_RECORD_PAYLOAD_SIZE);
    return 0;
}


/* Create the hash for looking up type definitions */

struct trace_type_definition_mapped {
    const struct trace_type_definition* def;
    map_t map;
};


static struct trace_type_definition_mapped * new_trace_type_definition_mapped(const struct trace_type_definition* def) {
    struct trace_type_definition_mapped* ptr =
        (struct trace_type_definition_mapped*) malloc(sizeof(struct trace_type_definition_mapped));

    if (NULL != ptr) {
    	ptr->def = def;
    	ptr->map = NULL;
    }

    return ptr;
}


static int init_types_hash(struct trace_parser_buffer_context *context) {

	context->type_hash = hashmap_new();
	if (NULL == context->type_hash) {
		return -1;
	}

	for (unsigned int i = 0; i < context->metadata->type_definition_count; i++) {
		int rc = MAP_OK;
		struct trace_type_definition_mapped *trace_type_def = new_trace_type_definition_mapped(&context->types[i]);
		if (NULL != trace_type_def) {
			rc = hashmap_put(context->type_hash,
							 context->types[i].type_name,
							 trace_type_def);
		}
		else {
			rc = MAP_OMEM;
		}

		if (MAP_OK != rc) {
			if (MAP_OMEM == rc) {
				errno = ENOMEM;
			}
			hashmap_free(context->type_hash);
			context->type_hash = NULL;
			return -1;
		}
	}

	return 0;
}

static int accumulate_metadata(trace_parser_t *parser, const struct trace_record *rec, trace_parser_event_handler_t handler, void *arg)
{
    struct trace_parser_buffer_context *context = get_buffer_context_by_pid(parser, rec->pid);
    if (NULL == context) {
        return 0;
    }
    
    if (rec->termination & TRACE_TERMINATION_LAST) {
        // Reached end of accumulation. The accumulated offset should be identical to the total size of the metadata
        if (context->metadata_size != context->current_metadata_offset) {
        	errno = EINVAL;
            return -1;
        }

        relocate_metadata_for_fmt_version(
        		context->metadata->base_address,
        		context->metadata, context->metadata->data,
        		context->metadata->log_descriptor_count,
        		context->metadata->type_definition_count,
        		parser->file_info.format_version);

        context->metadata_log_desciptor_size = get_log_descriptor_size(parser->file_info.format_version);
        context->descriptors = (struct trace_log_descriptor *) context->metadata->data;
        context->types = (struct trace_type_definition *) ((char *) context->metadata->data + context->metadata_log_desciptor_size * context->metadata->log_descriptor_count);
        if (strcmp(context->metadata->name, "xn-infinidat-core") == 0)
        	trace_array_strcpy(context->name, "core");
        else
        	trace_array_strcpy(context->name, context->metadata->name);
        // context->name[sizeof(context->name) - 1] = '\0';

        if (0 != init_types_hash(context)) {
        	return -1;
        }
        return handler(parser, TRACE_PARSER_FOUND_METADATA, context, arg);
    } else {
        return append_metadata(context, rec);
    }
}

static struct trace_record_accumulator *get_accumulator(trace_parser_t *parser, const struct trace_record *rec)
{
    int i;
    struct trace_record_accumulator *accumulator;
    for (i = 0; i < RecordsAccumulatorList__element_count(&parser->records_accumulators); i++) {
        RecordsAccumulatorList__get_element_ptr(&parser->records_accumulators, i, &accumulator);
        if (accumulator->tid == rec->tid && accumulator->ts == rec->ts && accumulator->severity == rec->severity) {
            return accumulator;
        }
    }

    return NULL;
}

static void free_accumulator(trace_parser_t *parser, const struct trace_record *rec)
{
    int i;
    struct trace_record_accumulator *accumulator;

    if (NULL == rec) {
    	return;
    }

    for (i = 0; i < RecordsAccumulatorList__element_count(&parser->records_accumulators); i++) {
        RecordsAccumulatorList__get_element_ptr(&parser->records_accumulators, i, &accumulator);
        if (accumulator->tid == rec->tid && rec->ts == accumulator->ts && accumulator->severity == rec->severity) {
            RecordsAccumulatorList__remove_element(&parser->records_accumulators, i);
            return;
        }
    }
}

static struct trace_record *accumulate_record(trace_parser_t *parser, const struct trace_record *rec, int forward)
{
    struct trace_record_accumulator *accumulator = get_accumulator(parser, rec);
    if ((accumulator == NULL) && rec->termination == (TRACE_TERMINATION_FIRST | TRACE_TERMINATION_LAST)) {
        return (struct trace_record *)rec;
    }

    if (NULL == accumulator) {
        if (!(rec->termination & TRACE_TERMINATION_FIRST)) {
            return NULL;
        }        

        if (!RecordsAccumulatorList__insertable(&parser->records_accumulators)) {
            RecordsAccumulatorList__remove_element(&parser->records_accumulators, 0);
        }

        int rc = RecordsAccumulatorList__allocate_element(&parser->records_accumulators);
        if (0 != rc) {
            return NULL;
        }
        
        RecordsAccumulatorList__get_element_ptr(&parser->records_accumulators, RecordsAccumulatorList__last_element_index(&parser->records_accumulators), &accumulator);
        accumulator->tid = rec->tid;
        accumulator->ts = rec->ts;
        accumulator->severity = rec->severity;
        accumulator->data_offset = TRACE_RECORD_HEADER_SIZE;

        memcpy(accumulator->accumulated_data, (char *) rec, TRACE_RECORD_HEADER_SIZE);
    }

    if (accumulator->data_offset + TRACE_RECORD_PAYLOAD_SIZE >= sizeof(accumulator->accumulated_data)) {
        return NULL;
    }

    if (forward) {
        memcpy(accumulator->accumulated_data + accumulator->data_offset, rec->u.payload, TRACE_RECORD_PAYLOAD_SIZE);
    } else {
        memmove(accumulator->accumulated_data + TRACE_RECORD_HEADER_SIZE + sizeof(rec->u.payload), accumulator->accumulated_data + TRACE_RECORD_HEADER_SIZE, accumulator->data_offset - TRACE_RECORD_HEADER_SIZE);
        memcpy(accumulator->accumulated_data + TRACE_RECORD_HEADER_SIZE, rec->u.payload, sizeof(rec->u.payload));
    }
    
    accumulator->data_offset += sizeof(rec->u.payload);

    if ((rec->termination & TRACE_TERMINATION_LAST && forward) ||
        (rec->termination & TRACE_TERMINATION_FIRST && !forward)) {
        return (struct trace_record *) accumulator->accumulated_data;
    } else {
        return NULL;
    }
}

struct log_occurrences {
    char template[512];
    unsigned int occurrences;
};


typedef struct log_stats {
    struct log_occurrences *logs;
    unsigned int max_log_count;
    unsigned int unique_count;
    unsigned int record_count;
    unsigned long long lost_records;
    unsigned int record_count_by_severity[TRACE_SEV__MAX];
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

static void dump_stats_pool(const log_stats_pool_t stats_pool)
{
    unsigned int i, j;
    char header[512];
    char underline[512];
    const struct log_stats *stats;
    for (i = 0; i < LOG_STATS_POOL_LENGTH; i++) {
        if (!stats_pool[i].allocated) {
            continue;
        }
        
        snprintf(header, sizeof(header), "Statistics for buffer %s [%d]\n",
                 stats_pool[i].data.buffer_context->name,
                 stats_pool[i].data.buffer_context->id);
        memset(underline, '-', strlen(header));
        underline[strlen(underline)] = '\0';
        printf("%s", header);
        printf("%s\n", underline);

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
            if (stats->logs[j].occurrences) {
                printf("%-10d : %-100s\n", stats->logs[j].occurrences, stats->logs[j].template);
            }
        }

        printf("\n\n");
    }
}

struct dump_context_s {
    int tail;
    int current_severity;
    char formatted_record[1024 * 20];
};


static const char* get_type_name(const struct trace_parser_buffer_context *context, const char *type_name, unsigned int value)
{
    any_t ptr ;

    /* Note: hashmap_get silently circumvents the const-ness of context, but we do this carefully  */
    int rc = hashmap_get(context->type_hash, type_name, &ptr);
    if (rc != MAP_OK)
        return NULL;

    struct trace_type_definition_mapped* type = (struct trace_type_definition_mapped*) ptr;

    if (type->map == 0) {
        type->map = hashmap_new();
        if (NULL != type->map) {
			for (int i = 0; NULL !=  type->def->enum_values[i].name; i++) {
				rc = hashmap_put_int(type->map,
                                     type->def->enum_values[i].value,
                                     (any_t) type->def->enum_values[i].name);
				if (MAP_OK != rc) {
					break;
				}
			}
        }
        else {
        	rc = MAP_OMEM;
        }

        if (MAP_OMEM == rc) {
        	errno = ENOMEM;
        	hashmap_free(type->map);
        	type->map = 0;
        }
    }

    if (rc == MAP_OK)
    	rc = hashmap_get_int(type->map, value, &ptr);

    if (rc != MAP_OK)
        return NULL;

    return (const char*) ptr;
}

static int format_typed_params(
		const trace_parser_t *parser,
		const struct trace_parser_buffer_context *context,
		const struct trace_record_typed *typed_record,
		int *bytes_processed,	/* Output parameter. A negative value signals an error */
        out_fd* out,
		bool_t describe_params)
{
    unsigned int metadata_index = typed_record->log_id;
    const unsigned char *pdata = typed_record->payload;
    const struct trace_log_descriptor *log_desc;
    const struct trace_param_descriptor *param;
    const int color_bool = parser->color;

    if (metadata_index >= context->metadata->log_descriptor_count) {
        SAY_COL(out, RED_B);
        SAY_F(out, "<<< Invalid Metadata %d >>>", metadata_index);
        SAY_COL(out, ANSI_RESET);
        
        *bytes_processed = -1;
        errno = EILSEQ;
        return out->i;
    }

    log_desc = get_log_descriptor(context, metadata_index);

    enum trace_log_descriptor_kind trace_kind = log_desc->kind;
    const char *delimiter = trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY ? ", " : " ";
    int first = 1;
    for (param = log_desc->params; (param->flags != 0); param++) {
        int put_delimiter = 1; // (param + 1)->flags != 0 ;
        
        if (first) {
            if      (trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY)
                SAY_S  (out, "--> ");
            else if (trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_LEAVE) 
                SAY_S  (out, "<-- ");
        }

        if (param->flags & TRACE_PARAM_FLAG_NAMED_PARAM) {
            if (trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY ||
                ! parser->hide_field_names) {
                SAY_COL(out, WHITE_B);
                SAY_S  (out, param->param_name);
                SAY_S  (out, "=");
            }
        }

        switch (param->flags &
                (TRACE_PARAM_FLAG_ENUM    |
                 TRACE_PARAM_FLAG_NUM_8   |
                 TRACE_PARAM_FLAG_NUM_16  |
                 TRACE_PARAM_FLAG_NUM_32  |
                 TRACE_PARAM_FLAG_NUM_64  |
                 TRACE_PARAM_FLAG_CSTR    |
                 TRACE_PARAM_FLAG_VARRAY  |
                 TRACE_PARAM_FLAG_NESTED_LOG)) {

        case TRACE_PARAM_FLAG_NESTED_LOG: {
            if (describe_params) {
                SAY_COL(out, WHITE_B);
                SAY_F  (out, "{<%s>}", param->type_name);
                SAY_COL(out, ANSI_RESET);
            }
            else {
                SAY_COL(out, WHITE_B);
                SAY_S  (out, "{ ");
                SAY_COL(out, ANSI_RESET); /* before __REPR__'s const string */
                int _bytes_processed = 0;
                format_typed_params(parser, context, (const struct trace_record_typed *) pdata, &_bytes_processed, out, FALSE);
                if (_bytes_processed <= 0) {
                	*bytes_processed = -1;
                	break;
                }
                pdata += _bytes_processed;
                SAY_COL(out, WHITE_B);
                SAY_S  (out, " }");
            }
        } break;
        
        case TRACE_PARAM_FLAG_CSTR: {
            if (param->const_str) {
                if (((trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY) ||
                     (trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_LEAVE)) && first) {

                    SAY_COL(out, YELLOW_B);
                    SAY_S  (out, param->const_str);
                    SAY_COL(out, ANSI_RESET);
                    SAY_C  (out, '(');
                    first = 0;
                    if ((param + 1)->flags == 0) 
                        SAY_C  (out, ')');
                    continue;
                }
                else {
                    SAY_S  (out, param->const_str);
                    if (ends_with_equal(out))
                        put_delimiter = 0;
                }
            }
            else
                SAY_S  (out, "<cstr?>");
        } break;
        
        case TRACE_PARAM_FLAG_VARRAY: {
            if (describe_params) {
                SAY_COLORED(out, "<vstr>", CYAN_B);
            }
            else {
                if (param->flags & TRACE_PARAM_FLAG_STR) {
                    SAY_COL(out, CYAN_B);
                    SAY_C  (out, '\"');
                }

                unsigned char continuation = FALSE;
                do {
                    unsigned char sl = (*(unsigned char *)pdata);
                    const unsigned char CONTINUATION_MASK = 0x80;
                    const unsigned char LENGTH_MASK = CONTINUATION_MASK - 1;

                    unsigned char len = sl & LENGTH_MASK;
                    continuation = 		sl & CONTINUATION_MASK;
                    pdata ++;
                    if (param->flags & TRACE_PARAM_FLAG_STR) {
                        SAY_COL(out, CYAN_B);
                        SAY_ESCAPED_S(out, (const char*) pdata, len);
                    }
                    pdata += len;

                } while (continuation);

                if (param->flags & TRACE_PARAM_FLAG_STR) {
					SAY_C  (out, '\"');
					SAY_COL(out, ANSI_RESET);
				}
            }
        } break;
        
            /* integer data */
#define GET_PDATA_VAL(TYPE) const TYPE _val = (*(const TYPE*)pdata); pdata += sizeof(_val)

#define DISPLAY_VAL(TYPE)                               \
        do if (describe_params) {                          \
            SAY_COLORED(out, "<" #TYPE ">", CYAN_B);    \
        }                                               \
        else {                                          \
            GET_PDATA_VAL(unsigned TYPE);               \
            SAY_INT(out, color_bool, parser->always_hex, param->flags, _val); \
        } while(0)

        case TRACE_PARAM_FLAG_ENUM: {
            if (describe_params) {
                SAY_COL(out, CYAN_B);
                SAY_F  (out, "<%s>", param->type_name);
                SAY_COL(out, ANSI_RESET);
            }
            else {
                GET_PDATA_VAL(unsigned int);
                const char* name = get_type_name(context, param->type_name, _val);
                SAY_COL(out, BLUE_B);
                if (name)
                    SAY_S  (out, name);
                else
                    SAY_F  (out, "<enum:%d>", _val);
            }
        } break;
        
        case TRACE_PARAM_FLAG_NUM_8:
            DISPLAY_VAL(char);
            break;
        
        case TRACE_PARAM_FLAG_NUM_16:
            DISPLAY_VAL(short);
            break;

        case TRACE_PARAM_FLAG_NUM_32:
            DISPLAY_VAL(int);
            break;

        case TRACE_PARAM_FLAG_NUM_64: {
            if (describe_params) {
                SAY_COLORED(out, "<long long>", CYAN_B);
            }
            else {
                const bool_t hex_bool = (param->flags & TRACE_PARAM_FLAG_HEX) || parser->always_hex;
                GET_PDATA_VAL(unsigned long long);
                SAY_COL(out, CYAN_B);
                SAY_F  (out, ( hex_bool ? "0x%llx" : (param->flags & TRACE_PARAM_FLAG_UNSIGNED) ? "%llu" : "%lld" ), _val);
            }
        } break;

        default: break;
        }
        
        if ((param + 1)->flags == 0 && (trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY ||
                                        trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_LEAVE)) {
            SAY_COL(out, ANSI_RESET);
            SAY_S  (out, ")");
        }

        if ( put_delimiter) {
            SAY_COL(out, ANSI_RESET);
            SAY_S  (out, delimiter);
        }
    }

    if (parser->show_function_name &&
        log_desc->function &&
        log_desc->function[0] ) {
        SAY_COL(out, WHITE_B);
        SAY_C  (out, ' ');
        SAY_C  (out, '<');
        SAY_S  (out, log_desc->function);
        SAY_C  (out, '>');
    }
    SAY_COL(out, ANSI_RESET);
    (*bytes_processed) = (const char *) pdata - (const char *) typed_record;
    return out->i; // total_length;
}

#undef DISPLAY_VAL
#undef GET_PDATA_VAL

static const char * severity_to_str(unsigned int sev, int color_bool) {

	static const char* sevs_colored[] = {
        GREY     "----",

#define TRACE_SEV_X(ignored, name) TRACE_SEV_##name##_DISPLAY_COLOR TRACE_SEV_##name##_DISPLAY_STR,

        TRACE_SEVERITY_DEF

#undef TRACE_SEV_X

    };
    static const char* sevs[] = {
        "----",
#define TRACE_SEV_X(ignored, name) TRACE_SEV_##name##_DISPLAY_STR,

        TRACE_SEVERITY_DEF

#undef TRACE_SEV_X

    };

    enum trace_severity mapped_sev = trace_sev_mapping[sev];
    return
        (mapped_sev < TRACE_SEV_FUNC_TRACE || mapped_sev > TRACE_SEV__MAX ) ?
        "???" :
        color_bool ?
        sevs_colored[mapped_sev - TRACE_SEV_FUNC_TRACE] :
        sevs        [mapped_sev - TRACE_SEV_FUNC_TRACE] ;
}

static int TRACE_PARSER__format_typed_record(
		const trace_parser_t *parser,
		const struct trace_parser_buffer_context *context,
		const struct trace_record *record,
        out_fd* out )
{

    const int color_bool = parser->color;
    const int timestamp_bool = parser->show_timestamp;
    SAY_COL(out, ANSI_RESET);
    if (timestamp_bool) {
        SAY_S  (out, format_timestamp(record->ts, parser->nanoseconds_ts, parser->compact_traces));

        SAY_S  (out, " [");
        SAY_COL(out, MAGENTA);

        if (parser->compact_traces)
            SAY_F  (out, "%5d", record->pid);
        else
            SAY_S  (out, context ? context->name : "<? unknown>");
        SAY_COL(out, GREY);
        SAY_S  (out, ":");
    }
    else {
        SAY_S  (out, "[");
        SAY_COL(out, MAGENTA);
    }
    SAY_COL(out, BLUE_B);
    SAY_F  (out, "%5d", record->tid);
    SAY_COL(out, ANSI_RESET);
    SAY_S  (out, "] ");

    SAY_S  (out, severity_to_str(record->severity, color_bool));
    // SAY_COL(out, ANSI_RESET);
    SAY_S  (out, ": ");

    /*
    if (parser->indent)
        for (int i = 4*MAX(record->nesting, 0); i; i--)
            SAY_C  (out, ' ');
    */

    int bytes_processed = 0;
    if (context)
        format_typed_params(parser, context, (const struct trace_record_typed *) record->u.payload, &bytes_processed, out, FALSE);
    else
        SAY_COLORED(out, "<?>", RED_B);

    SAY_COL(out, ANSI_RESET);
    SAY_C  (out, '\n');

    if (bytes_processed <= 0) {
    	return -1;
    }
    return out->i; // total_length;
}

static int process_typed_record(
		trace_parser_t *parser,
		bool_t accumulate_forward,
		const struct trace_record *rec,
		struct trace_record **out_record,
		struct trace_parser_buffer_context **buffer)
{
    struct trace_record *complete_record = accumulate_record(parser, rec, accumulate_forward);
    if (!complete_record) {
        return EINVAL;
    }

    *buffer = get_buffer_context_by_pid(parser, complete_record->pid);
    complete_record->termination |= TRACE_TERMINATION_LAST;
    *out_record = complete_record;

    if (NULL == *buffer) {
    	return ESRCH;
    }

    return 0;
}

// typedef int (*typed_record_processor_t)(trace_parser_t *parser, const struct trace_record *record, void *arg);

static void ignore_next_n_records(trace_parser_t *parser, unsigned int ignore_count)
{
    parser->ignored_records_count = ignore_count;
}

static bool_t match_record_dump_with_match_expression(
		const struct trace_record_matcher_spec_s *matcher,
		const struct trace_record *record,
		const struct trace_parser_buffer_context *buffer_context);

static void process_buffer_chunk_record(trace_parser_t *parser, const struct trace_record *buffer_chunk)
{
    const struct trace_record_buffer_dump *bd = &buffer_chunk->u.buffer_chunk;
    
    if (bd->severity_type) {
        if (parser->stream_type == TRACE_INPUT_STREAM_TYPE_NONSEEKABLE && !(match_record_dump_with_match_expression(parser->record_filter, buffer_chunk, NULL))) {
            ignore_next_n_records(parser, bd->records);
        }
    }
}

static bool_t file_open(const trace_parser_t *parser)
{
    if (parser->file_info.fd >= 0) {
        return TRUE;
    } else {
        return FALSE;
    }
}

static long long trace_file_current_offset(const trace_parser_t *parser)
{
    if (!file_open(parser)) {
    	errno = EBADF;
        return -1;
    }

    return parser->file_info.current_offset / sizeof(struct trace_record);
}

static int read_record_at_offset(trace_parser_t *parser, long long offset, struct trace_record *record)
{
    parser->file_info.current_offset = offset * sizeof(struct trace_record);
    return read_next_record(parser, record);
}

static int process_metadata(trace_parser_t *parser, const struct trace_record *record)
{
    long long original_offset = trace_file_current_offset(parser);
    const struct trace_record_buffer_dump *buffer_chunk;
    buffer_chunk = &record->u.buffer_chunk;
    int rc = 0;
    
    long long new_offset;
    new_offset = TRACE_PARSER__seek(parser, buffer_chunk->last_metadata_offset, SEEK_SET);
    if (-1 == new_offset) {
        rc = -1;
        goto Exit;
    }

    struct trace_record tmp_record;
    rc = read_next_record(parser, &tmp_record);
    if (0 != rc) {
        goto Exit;
    }

    if (tmp_record.rec_type != TRACE_REC_TYPE_METADATA_HEADER) {
        rc = -1;
        goto Exit;
    }

    rc = metadata_info_started(parser, &tmp_record);
    if (0 != rc) {
        goto Exit;
    }

    do {
        rc = read_next_record(parser, &tmp_record);
        if (0 != rc) {
            goto Exit;
        }

        if (tmp_record.rec_type != TRACE_REC_TYPE_METADATA_PAYLOAD) {
            goto Exit;
        }

        rc = accumulate_metadata(parser, &tmp_record, parser->event_handler, parser->arg);
        if (0 != rc) {
            goto Exit;
        }
    } while (!(tmp_record.termination & TRACE_TERMINATION_LAST));
    
Exit:
	if (TRACE_PARSER__seek(parser, original_offset, SEEK_SET) == -1) {
		return -1;
	}
    return rc;
}

static int process_metadata_if_needed(trace_parser_t *parser, const struct trace_record *record)
{
    if (NULL != get_buffer_context_by_pid(parser, record->pid)) {
        return 0;
    }

    int rc = process_metadata(parser, record);
    return rc;
}

static bool_t match_record_dump_with_match_expression(
		const struct trace_record_matcher_spec_s *matcher,
		const struct trace_record *record,
		const struct trace_parser_buffer_context *buffer_context)
{
    return trace_filter_match_record_chunk(matcher, record, buffer_context->name);
}

static int process_dump_header_record(
		trace_parser_t *parser,
		const struct trace_record_matcher_spec_s *filter,
		const struct trace_record *record,
		trace_parser_event_handler_t handler,
		void *arg)
{
    const struct trace_record_dump_header *dump_header = &record->u.dump_header;
    struct trace_record_buffer_dump *buffer_chunk = NULL;
    struct trace_record tmp_record;
    unsigned int i = 0;

    int rc = (int) TRACE_PARSER__seek(parser, dump_header->first_chunk_offset, SEEK_SET);
    if (-1 == rc) {
        return -1;
    }

    long long current_offset = trace_file_current_offset(parser);
    long long end_offset = dump_header->total_dump_size + trace_file_current_offset(parser);
    parser->buffer_dump_context.end_offset = end_offset;
    parser->buffer_dump_context.previous_dump_offset = dump_header->prev_dump_offset;

    while (current_offset < end_offset) {
        if (i >= ARRAY_LENGTH(parser->buffer_dump_context.record_dump_contexts)) {
            return -1;
        }

        rc = read_next_record(parser, &tmp_record);
        if (0 != rc) {
            return -1;
        }

        if (tmp_record.rec_type != TRACE_REC_TYPE_BUFFER_CHUNK) {
            return -1;
        }

        
        buffer_chunk = &tmp_record.u.buffer_chunk;

        rc = process_metadata_if_needed(parser, &tmp_record);
        if (0 != rc) {
            return -1;
        }

        struct trace_parser_buffer_context *buffer_context = get_buffer_context_by_pid(parser, tmp_record.pid);
        if (NULL == buffer_context) {
            return -1;
        }
        
        if (!(!parser->silent_mode && match_record_dump_with_match_expression(filter, &tmp_record, buffer_context))) {
            current_offset = TRACE_PARSER__seek(parser, buffer_chunk->records, SEEK_CUR);
            if (current_offset == -1) {
            	return -1;
            }
            continue;
        }

        if (handler) {
            struct parser_buffer_chunk_processed chunk_processed = {buffer_chunk, buffer_context};
            handler(parser, TRACE_PARSER_BUFFER_CHUNK_HEADER_PROCESSED, &chunk_processed, arg);
        }
        
        parser->buffer_dump_context.record_dump_contexts[i].start_offset = trace_file_current_offset(parser);
        parser->buffer_dump_context.record_dump_contexts[i].current_offset = parser->buffer_dump_context.record_dump_contexts[i].start_offset;
        parser->buffer_dump_context.record_dump_contexts[i].end_offset = parser->buffer_dump_context.record_dump_contexts[i].start_offset + buffer_chunk->records;
        current_offset = TRACE_PARSER__seek(parser, buffer_chunk->records, SEEK_CUR);
        if (-1 == current_offset) {
            return -1;
        }
        i++;
    }

    if (i) {
        current_offset = TRACE_PARSER__seek(parser, parser->buffer_dump_context.record_dump_contexts[0].start_offset, SEEK_SET);
    } else {
        current_offset = TRACE_PARSER__seek(parser, dump_header->first_chunk_offset - 1 + dump_header->total_dump_size, SEEK_SET);
    }

    
    if (current_offset == -1) {
        return -1;
    } else {
        parser->buffer_dump_context.num_chunks = i;
        return 0;
    }
}

static bool_t discard_record_on_nonseekable_stream(trace_parser_t *parser)
{
    if (parser->ignored_records_count) {
        parser->ignored_records_count--;
        return TRUE;
    } else {
        return FALSE;
    }
}

#define AFTER_COUNT_COUNT 20

typedef struct {
    int keep_going;
    long long quota;
    int after_count_all;
    int after_count_cnt[AFTER_COUNT_COUNT];
    short unsigned int after_count_tid[AFTER_COUNT_COUNT];
} iter_t;

static bool_t after_count_push(iter_t* iter, short unsigned int tid, int count) {
    if (! iter || count <= 0) return TRUE;

    int all = iter->after_count_all;
    for (int i = 0; all > 0&& i < AFTER_COUNT_COUNT; i++) {
        if (iter->after_count_tid[i] == tid) {
            iter->after_count_all += count - iter->after_count_cnt[i];
            iter->after_count_cnt[i] = count;
            return TRUE;
        }
        all -= iter->after_count_cnt[i];
    }
    if (all) {
        /* warn ? */
        //        fprintf(stderr, "Warning: after count has %i global leftovers\n", all);
        iter->after_count_all -= all;
    }
    for (int i = 0; i < AFTER_COUNT_COUNT; i++)
        if (iter->after_count_tid[i] == 0) {
            iter->after_count_tid[i] = tid;
            iter->after_count_cnt[i] = count;
            iter->after_count_all += count;
            return TRUE;
        }

    fprintf(stderr, "Warning: after count exceeded %i thread ids\n", AFTER_COUNT_COUNT);
    return TRUE;
}

static bool_t after_count_pop(iter_t* iter, short unsigned int tid) {
    if (! iter) return FALSE;

    int all = iter->after_count_all;
    for (int i = 0; all > 0 && i < AFTER_COUNT_COUNT; i++) {
        if (iter->after_count_tid[i] == tid) {
            if (-- iter->after_count_cnt[i] <= 0)
                iter->after_count_tid[i] = 0;
            iter->after_count_all --;
            return TRUE;
        }
        all -= iter->after_count_cnt[i];
    }
    if (all) {
        /* warn ? */
        //        fprintf(stderr, "Warning: after count has %i global leftovers\n", all);
        iter->after_count_all -= all;
    }
    return FALSE;
}
#undef AFTER_COUNT_COUNT

static bool_t match_record_with_match_expression(
		const struct trace_record_matcher_spec_s *matcher,
		const struct trace_parser_buffer_context *buffer,
		const struct trace_record *record,
        iter_t * iter)
{

    long long *quota = NULL;
    bool_t *keep_going = NULL;

    if (NULL != iter) {
        quota = &iter->quota;
        keep_going = &iter->keep_going;
    }

    return trace_filter_match_record(matcher, buffer, record, quota, keep_going);
}

static int process_single_record(
		trace_parser_t *parser,
		const struct trace_record_matcher_spec_s *filter,
		const struct trace_record *record,
		bool_t *complete_typed_record_found,
		bool_t accumulate_forward,
		trace_parser_event_handler_t handler,
		void *arg,
        iter_t* iter)
{
    int rc = 0;
    struct trace_parser_buffer_context *buffer = NULL;
    struct trace_record *complete_record = NULL;
    struct parser_complete_typed_record complete_rec;
    *complete_typed_record_found = FALSE;

    switch (record->rec_type) {
    case TRACE_REC_TYPE_UNKNOWN:
        rc = handler(parser, TRACE_PARSER_UNKNOWN_RECORD_ENCOUNTERED, &record, arg);
        break;
    case TRACE_REC_TYPE_TYPED:
        if (discard_record_on_nonseekable_stream(parser)) {
            rc = 0;
            break;
        }

        rc = process_typed_record(parser, accumulate_forward, record, &complete_record, &buffer);
        switch (rc) {
        case 0: /* We passed a complete record */
            complete_rec.buffer = buffer;
            complete_rec.record = complete_record;
            if ((!parser->silent_mode &&
                        match_record_with_match_expression(filter, buffer, complete_record, iter) &&
                 after_count_push(iter, complete_record->tid, parser->after_count)) ||
                (after_count_pop (iter, complete_record->tid))) {

            	rc = handler(parser, TRACE_PARSER_COMPLETE_TYPED_RECORD_PROCESSED, &complete_rec, arg);
                if (0 == rc) {
                	*complete_typed_record_found = TRUE;
                }
            }

            free_accumulator(parser, complete_record);
            break;

        case EINVAL:  /* We passed a partial record, this is normal */
        	rc = 0;
        	break;

        default:
        	errno = rc;
        	rc = -1;
        	break;
        }

        break;
    case TRACE_REC_TYPE_FILE_HEADER:
    	trace_array_strcpy(parser->file_info.machine_id, record->u.file_header.machine_id);
        parser->file_info.format_version = record->u.file_header.format_version;
        break;
    case TRACE_REC_TYPE_METADATA_HEADER:
        rc = metadata_info_started(parser, record);
        break;
    case TRACE_REC_TYPE_METADATA_PAYLOAD:
        rc = accumulate_metadata(parser, record, handler, arg);
        break;
    case TRACE_REC_TYPE_DUMP_HEADER:
        process_dump_header_record(parser, filter, record, handler, arg);
        break;
    case TRACE_REC_TYPE_BUFFER_CHUNK:
        process_buffer_chunk_record(parser, record);
        break;
    case TRACE_REC_TYPE_END_OF_FILE:
        rc = ENODATA;
        break;
    default:
        rc = -1;
        break;
    }

    return rc;
}

static bool_t inside_record_dump(const trace_parser_t *parser)
{
    unsigned int i;
    for (i = 0; i < parser->buffer_dump_context.num_chunks; i++) {
        if (parser->buffer_dump_context.record_dump_contexts[i].current_offset < parser->buffer_dump_context.record_dump_contexts[i].end_offset) {
            return TRUE;
        }
    }

    return FALSE;
}

static int read_smallest_ts_record(trace_parser_t *parser, struct trace_record *record)
{
    struct trace_record tmp_record;
    unsigned int i;
    unsigned long long min_ts = ULLONG_MAX;
    int rc;
    unsigned int index_of_minimal_chunk = 0;

    for (i = 0; i < parser->buffer_dump_context.num_chunks; i++) {
        if (parser->buffer_dump_context.record_dump_contexts[i].current_offset >= parser->buffer_dump_context.record_dump_contexts[i].end_offset) {
            continue;
        }

        rc = read_record_at_offset(parser, parser->buffer_dump_context.record_dump_contexts[i].current_offset, &tmp_record);
        if (0 != rc) {
            return -1;
        }

        if (tmp_record.ts < min_ts) {
            min_ts = tmp_record.ts;
            index_of_minimal_chunk = i;
            memcpy(record, &tmp_record, sizeof(*record));
        }
    }
    
    if (min_ts == ULLONG_MAX) {
        memset(record, 0, sizeof(*record));
    } else {
        parser->buffer_dump_context.record_dump_contexts[index_of_minimal_chunk].current_offset++;
    }

    if (!inside_record_dump(parser)) {
        if (TRACE_PARSER__seek(parser, parser->buffer_dump_context.end_offset, SEEK_SET) == -1) {
        	return -1;
        }
    }

    return 0;
}

static int restore_parsing_buffer_dump_context(trace_parser_t *parser, const struct buffer_dump_context_s *dump_context)
{
    memcpy(&parser->buffer_dump_context, dump_context, sizeof(parser->buffer_dump_context));
    return TRACE_PARSER__seek(parser, parser->buffer_dump_context.file_offset, SEEK_SET);
}

static int process_next_record_from_file(trace_parser_t *parser, const struct trace_record_matcher_spec_s *filter,
                                         trace_parser_event_handler_t event_handler, void *arg, iter_t* iter)
{
    struct trace_record record;

    bool_t complete_typed_record_processed = FALSE;
    int rc = -1;
    // unsigned long records_processed = 0;
    
    while (!iter || iter->keep_going) {
        if (inside_record_dump(parser)) {
            rc = read_smallest_ts_record(parser, &record);
            if (record.ts == 0) {
                if (-1 == TRACE_PARSER__seek(parser, parser->buffer_dump_context.end_offset, SEEK_SET)) {
                    return -1;
                }
                continue;
            }
        } else {
            rc = read_next_record(parser, &record);
        }
        
        if (0 != rc) {
            break;
        }

        rc = process_single_record(parser, filter, &record, &complete_typed_record_processed, TRUE, event_handler, arg, iter);
        if (0 != rc) {
            break;
        }
        
        if (complete_typed_record_processed) {
            return 0;
        }
    }

    return rc;
}

static void say_new_file(out_fd* out, trace_parser_t *parser, unsigned long long ts) {
    const int color_bool = parser->color;
    SAY_COL(out, ANSI_RESET);
    if (parser->show_timestamp)
        SAY_S  (out, format_timestamp(MAX(ts, 0ULL), parser->nanoseconds_ts, parser->compact_traces));
    SAY_S  (out, " [");
    SAY_COL(out, BLUE_B);
    SAY_S  (out, "Traces New Filename");
    SAY_COL(out, ANSI_RESET);
    SAY_S  (out, "] ");
    SAY_COL(out, WHITE_B);
    SAY_S  (out, parser->show_filename);
    SAY_COL(out, ANSI_RESET);
    SAY_S  (out, "\n");
    parser->show_filename = 0;
}

static int dumper_event_handler(trace_parser_t *parser, enum trace_parser_event_e event, void *event_data, void __attribute__((unused)) *arg)
{
    if (parser->silent_mode) {
        return 0;
    }

    if (event != TRACE_PARSER_COMPLETE_TYPED_RECORD_PROCESSED) {
        return 0;
    }

    out_fd out;
    out_init(&out);
    struct parser_complete_typed_record *complete_typed_record = (struct parser_complete_typed_record *) event_data;

    if (parser->show_filename) 
        say_new_file(&out, parser, complete_typed_record->record->ts-1);

    int formatted_len = TRACE_PARSER__format_typed_record(parser, complete_typed_record->buffer, complete_typed_record->record, &out);
    if (formatted_len < 0) {
    	errno = ENOMEM;
    	fprintf(stderr, _F_RED_BOLD("Warning: Had to skip a record because it didn't fit in the buffer\n") _ANSI_DEFAULTS(""));
    	return -1;
    }
    out_flush(&out);
    return 0;
}

int TRACE_PARSER__dump(trace_parser_t *parser)
{
    struct dump_context_s dump_context;
    if (parser->stream_type != TRACE_INPUT_STREAM_TYPE_SEEKABLE_FILE) {
    	errno = EINVAL;
        return -1;
    }
    iter_t iter;
    bzero(&iter, sizeof(iter));
    iter.keep_going = 1;
    while (iter.keep_going) {
        int rc = process_next_record_from_file(parser, parser->record_filter, dumper_event_handler, &dump_context, &iter);
        if (0 != rc) {
            return rc;
        }
    }

    return 0;
}

int process_all_metadata(trace_parser_t *parser, trace_parser_event_handler_t handler)
{
    struct dump_context_s dump_context;
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

static int get_minimal_log_id_size(const struct trace_parser_buffer_context *context, unsigned int log_id, bool_t *exact_size)
{
    const struct trace_log_descriptor *log_desc;
    const struct trace_param_descriptor *param;
    int minimal_log_id_size = sizeof(log_id);
    if (log_id >= context->metadata->log_descriptor_count) {
        return -1;
    }

    log_desc = get_log_descriptor(context, log_id);

    *exact_size = TRUE;
    for (param = log_desc->params; (param->flags != 0); param++) {
        if (param->flags & TRACE_PARAM_FLAG_NESTED_LOG) {
            minimal_log_id_size = sizeof(log_id);
            *exact_size = FALSE;
            continue;
        }

        if (param->flags & TRACE_PARAM_FLAG_VARRAY) {
            minimal_log_id_size += 1;
            *exact_size = FALSE;
            continue;
        }
        
        if (param->flags & TRACE_PARAM_FLAG_ENUM) {
            minimal_log_id_size += sizeof(int);
            continue;
        }
        
        if (param->flags & TRACE_PARAM_FLAG_NUM_8) {
            minimal_log_id_size += sizeof(char);
            continue;
        }
        
        if (param->flags & TRACE_PARAM_FLAG_NUM_16) {
            minimal_log_id_size += sizeof(short);
            continue;
        }

        if (param->flags & TRACE_PARAM_FLAG_NUM_32) {
            minimal_log_id_size += sizeof(int);
            continue;
        }

        if (param->flags & TRACE_PARAM_FLAG_NUM_64) {
            minimal_log_id_size += sizeof(long long);
            continue;
        }        
    }

    return minimal_log_id_size;
}

static int log_id_to_log_template(trace_parser_t *parser, struct trace_parser_buffer_context *context, int log_id, char *formatted_record, int formatted_record_size)
{
    int total_length = 0;
    bool_t exact_size = FALSE;

    formatted_record[0] = '\0';

    const char *exact_indicator = "*";
    unsigned int minimal_log_size = get_minimal_log_id_size(context, log_id, &exact_size);
    if (!exact_size) {
        exact_indicator = "";
    }
    
#define APPEND_FORMATTED_TEXT(...) do {                                   \
        int _len_ = snprintf(&formatted_record[total_length],             \
                             formatted_record_size - total_length - 1,    \
                             __VA_ARGS__);                                \
        if (_len_ < 0 || _len_ >= formatted_record_size - total_length - 1) { errno = ENOMEM; return -1; } \
        total_length += _len_;                                            \
    } while (0);


    const struct trace_log_descriptor *descriptor = NULL;
    if (parser->file_info.format_version >= TRACE_FORMAT_VERSION_INTRODUCED_FILE_FUNCTION_METADATA) {
    	descriptor = get_log_descriptor(context, log_id);
    	const char *severity_str = severity_to_str(descriptor->severity, parser->color);
    	APPEND_FORMATTED_TEXT("%s ", severity_str);
    }

    if (parser->color) {
        APPEND_FORMATTED_TEXT(_F_MAGENTA("%-20s") _ANSI_DEFAULTS(" [") _F_BLUE_BOLD("%5d") _ANSI_DEFAULTS("] <%03d%-1s> "),
                              context->name, context->id, minimal_log_size, exact_indicator);
    } else {
        APPEND_FORMATTED_TEXT("%-20s [%5d] <%03d%-1s> ", context->name, context->id, minimal_log_size, exact_indicator);
    }
    

    struct trace_record_typed record;
    record.log_id = log_id;
    int bytes_processed = 0;

    if (parser->file_info.format_version >= TRACE_FORMAT_VERSION_INTRODUCED_FILE_FUNCTION_METADATA) {
    	APPEND_FORMATTED_TEXT("[%s:%u - %s()] ", descriptor->file, descriptor->line, descriptor->function);
    }
#undef APPEND_FORMATTED_TEXT
    out_fd out;
    out_init(&out);
    int ret = format_typed_params(parser, context, &record, &bytes_processed, &out, TRUE);
    if (ret < 0) {
    	formatted_record[0] = '\0';
    	return -1;
    }
    if (total_length + (int)out.i >= formatted_record_size) {
    	formatted_record[0] = '\0';
        errno = ENOMEM;
        return -1;
    }
    formatted_record += total_length;
    memcpy (formatted_record, out.buf, out.i);
    formatted_record[out.i] = '\0';
    return (bytes_processed > 0) ? 0 : -1;
}


static int dump_metadata(trace_parser_t *parser, enum trace_parser_event_e event, void *event_data, void __attribute__((unused)) *arg)
{
    if (event != TRACE_PARSER_FOUND_METADATA) {
        return 0;
    }

    struct trace_parser_buffer_context *context = (struct trace_parser_buffer_context *) event_data;
    unsigned int i;
    char formatted_template[512];
    for (i = 0; i < context->metadata->log_descriptor_count; i++) {
        log_id_to_log_template(parser, context, i, formatted_template, sizeof(formatted_template));
        if (printf("(%05d) %s\n", i, formatted_template) < 0) {
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

    stats->logs = malloc(buffer->metadata->log_descriptor_count * sizeof(struct log_occurrences));
    if (NULL == stats->logs) {
        return NULL;
    }

    memset(stats->logs, 0, buffer->metadata->log_descriptor_count * sizeof(struct log_occurrences));
    stats->max_log_count = buffer->metadata->log_descriptor_count;
    stats->buffer_context = buffer;
    return stats;
}

static int count_entries(trace_parser_t *parser, enum trace_parser_event_e event, void __attribute__((unused)) *event_data, void __attribute__((unused)) *arg)
{
    log_stats_pool_t *stats_pool = (log_stats_pool_t *) arg;
    struct log_stats *stats;
    char template[sizeof(stats->logs->template)];
    
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
    if (metadata_index >= stats->max_log_count) {
        abort();
    }

    if (stats->logs[metadata_index].template[0] == '\0') {
        log_id_to_log_template(parser, complete_typed_record->buffer, metadata_index, template, sizeof(template));
        trace_strncpy_and_terminate(stats->logs[metadata_index].template, template, sizeof(stats->logs[metadata_index].template));
        stats->logs[metadata_index].occurrences = 1;
        stats->unique_count++;
    } else {
        stats->logs[metadata_index].occurrences++;
    }
    
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

        free(stats_pool[i].data.logs);
    }
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
            break;
        }
    }

    dump_stats_pool(log_stats_pool);
    free_stats_pool(log_stats_pool);
    return 0;
}
#ifdef _USE_INOTIFY_
static int init_inotify(trace_parser_t *parser, const char *filename)
{

    int rc;
    rc = inotify_init();
    if (-1 == rc) {
        return -1;
    }

    parser->inotify_fd = rc;
    rc = inotify_add_watch(parser->inotify_fd, filename, IN_MODIFY);
    if (-1 == rc) {
        return -1;
    }

    parser->inotify_descriptor = rc;
    return 0;
}
#endif


static void init_trace_sev_mapping(void) {
    for (unsigned i = 0; i < ARRAY_LENGTH(trace_sev_mapping); i++) {
    	trace_sev_mapping[i] = TRACE_SEV_INVALID;
    }

    trace_sev_mapping[TRACE_SEV_FUNC_TRACE] = TRACE_SEV_FUNC_TRACE;
}

#define FILL_SEV_MAPPING_FOR_VER(ver) \
if (! sev_mapping_filled) { \
	SEVERITY_COMPAT_DEF(ver) \
	sev_mapping_filled = TRUE; \
	} \

int TRACE_PARSER__from_file(trace_parser_t *parser, bool_t wait_for_input, const char *filename, trace_parser_event_handler_t event_handler, void *arg)
{
    int rc;
    trace_parser_init(parser, event_handler, arg, TRACE_INPUT_STREAM_TYPE_SEEKABLE_FILE);
    if (wait_for_input) {
        parser->silent_mode = TRUE;
        parser->wait_for_input = TRUE;
    }

    rc = trace_parser_mmap_file(parser, filename);
    if (0 != rc) {
        return -1;
    }

    struct trace_record file_header;

    rc = read_file_header(parser, &file_header);
    if (0 != rc) {
        trace_parser_unmap_file(parser);
        return -1;
    }

    init_trace_sev_mapping();
    bool_t sev_mapping_filled = FALSE;

#define TRACE_SEV_X(num, name) \
		trace_sev_mapping[num] = TRACE_SEV_##name;


    parser->file_info.format_version = file_header.u.file_header.format_version;
    switch (parser->file_info.format_version) {
    case 0xA3:
    	parser->file_info.low_latency_mode = (0 != (file_header.u.file_header.flags & TRACE_FILE_HEADER_FLAG_LOW_LATENCY_MODE));
#if VER_HAS_SEVERITY_DEF(0xA3)
    	FILL_SEV_MAPPING_FOR_VER(0xA3)
    	/* No break - continue with the adjustments defined for earlier versions. */
#endif

    case 0xA2:
#if VER_HAS_SEVERITY_DEF(0xA2)
    	FILL_SEV_MAPPING_FOR_VER(0xA2)
#endif

    case 0xA1:
#if VER_HAS_SEVERITY_DEF(0xA1)
		FILL_SEV_MAPPING_FOR_VER(0xA1)
#endif

    	break;

#undef TRACE_SEV_X

    default:
    	trace_parser_unmap_file(parser);
    	errno = EFTYPE;
    	return -1;
    }
    
#ifdef _USE_INOTIFY_
    if (wait_for_input && ! parser->file_info.low_latency_mode && (0 != init_inotify(parser, filename))) {
     	fprintf(stderr, "Failed to set-up inotify because of the following error: %s\n", strerror(errno));
        return -1;
    }
#endif

    trace_strncpy_and_terminate(parser->file_info.filename, filename, sizeof(parser->file_info.filename));
    trace_array_strcpy(parser->file_info.machine_id, file_header.u.file_header.machine_id);
    return 0;
}

void TRACE_PARSER__fini(trace_parser_t *parser)
{
    if (file_open(parser)) {
        trace_parser_unmap_file(parser);
    }

    free_all_metadata(parser);
}

off64_t TRACE_PARSER__seek(trace_parser_t *parser,off64_t offset, int whence)
{
	off64_t absolute_offset = offset * sizeof(struct trace_record);
    if (parser->stream_type == TRACE_INPUT_STREAM_TYPE_NONSEEKABLE) {
    	errno = EINVAL;
        return -1;
    }
    
    if (!file_open(parser)) {
    	errno = EBADF;
        return -1;
    }

    off64_t new_offset;

    switch (whence) {
    case SEEK_SET:
    	new_offset = absolute_offset;
    	break;

    case SEEK_CUR:
    	new_offset = parser->file_info.current_offset + absolute_offset;
    	break;

    case SEEK_END:
    	new_offset = parser->file_info.end_offset + absolute_offset;
    	break;

    default:
    	errno = EINVAL;
    	return -1;
    }


    while (new_offset > parser->file_info.end_offset) {
    	if (! parser->wait_for_input) {
    		errno = ESPIPE;
    		return -1;
    	}

    	if (adjust_offset_for_added_data(parser) < 0) {
    		return -1;
    	}
    }

	parser->buffer_dump_context.file_offset = new_offset / sizeof(struct trace_record);
	parser->file_info.current_offset = new_offset;
	return parser->buffer_dump_context.file_offset;
}

/*
long long find_record_by_ts(trace_parser_t *parser, unsigned long long ts, long long min, long long max, unsigned long long *found_ts)
{
    struct trace_record record;
    memset(&record, 0, sizeof(record));

    record.rec_type = TRACE_REC_TYPE_UNKNOWN;
    long long mid = 0;
    *found_ts = 0;
    while (max >= min)
    {
    // calculate the midpoint for roughly equal partition 
        mid = (min + max) / 2;

        record.rec_type = TRACE_REC_TYPE_UNKNOWN;
        int rc = read_record_at_offset(parser, mid, &record);
        if (0 != rc) {
            return -1;
        }

        if  (record.ts < ts)
            min = mid + 1;
        else if (record.ts > ts)
            max = mid - 1;
        else {
            break;
        }
    }

    *found_ts = record.ts;
    return mid;
}

int get_previous_record_by_type_from_current_offset(trace_parser_t *parser, struct trace_record *record, enum trace_rec_type record_type)
{
    int rc;
    long long original_offset = trace_file_current_offset(parser);
    if (original_offset == -1) {
        return -1;
    }
    
    while (TRUE) {
        rc = TRACE_PARSER__seek(parser, -1, SEEK_CUR);
        if (-1 == rc) {
            rc = -1;
            break;
        }

        rc = read_next_record(parser, record);
        if (rc < 0) {
            rc = -1;
            break;
        }

        if (record->rec_type == record_type) {
            rc = 0;
            break;
        }
        
        rc = TRACE_PARSER__seek(parser, -1, SEEK_CUR);
        if (rc == -1) {
            break;
        }
    }
        
    if (-1 == TRACE_PARSER__seek(parser, original_offset, SEEK_SET)) {
    	return -1;
    }
    return rc;
}

int get_next_record_by_type_from_current_offset(trace_parser_t *parser, struct trace_record *record, enum trace_rec_type record_type)
{
    int rc;
    long long original_offset = trace_file_current_offset(parser);
    if (original_offset == -1) {
        return -1;
    }
    
    while (TRUE) {
        rc = read_next_record(parser, record);
        if (rc < 0) {
            rc = -1;
            break;
        }

        if (record->rec_type == record_type) {
            rc = 0;
            break;
        }
    }
        
    if (TRACE_PARSER__seek(parser, original_offset, SEEK_SET) == -1) {
    	return -1;
    }
    return rc;
}

static void set_record_dumps_ts(trace_parser_t *parser, unsigned long long ts)
{
    unsigned int i;
    for (i = 0; i < parser->buffer_dump_context.num_chunks; i++) {
        unsigned long long found_ts;
        long long new_offset = find_record_by_ts(parser, ts, parser->buffer_dump_context.record_dump_contexts[i].start_offset, parser->buffer_dump_context.record_dump_contexts[i].end_offset - 1, &found_ts);
        parser->buffer_dump_context.record_dump_contexts[i].current_offset = new_offset;
    }
}

int set_buffer_dump_context_from_ts(trace_parser_t *parser, struct trace_record_matcher_spec_s *filter, unsigned long long ts, long long new_offset)
{
    struct trace_record record;
    memset(&record, 0, sizeof(record));
    long long rc;
    rc = TRACE_PARSER__seek(parser, new_offset, SEEK_SET);
    if (-1 == rc) {
        return -1;
    }

    rc = get_previous_record_by_type_from_current_offset(parser, &record, TRACE_REC_TYPE_DUMP_HEADER);
    if (0 != rc) {
        rc = get_next_record_by_type_from_current_offset(parser, &record, TRACE_REC_TYPE_DUMP_HEADER);
    }
    
    if (0 != rc) {
        return -1;
    }

    rc = process_dump_header_record(parser, filter, &record, NULL, NULL);
    if (0 != rc) {
        return -1;
    }

    set_record_dumps_ts(parser, ts);
    return 0;
}
*/
