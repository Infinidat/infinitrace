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
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <assert.h>
#include <stdarg.h>
#include <sysexits.h>

#include <pthread.h>
#include <semaphore.h>

#include "parser.h"
#include "min_max.h"
#include "array_length.h"
#include "trace_defs.h"
#include "list_template.h"
#include "trace_metadata_util.h"
#include "object_pool.h"
#include "colors.h"
#include "string.h"
#include "timeformat.h"

#include "zlib.h"

/* print out */
typedef struct {
    char buf[0x2000];
    unsigned int i;
} out_fd;

static void out_init(out_fd* out) {
    out->i = 0;
}
static void out_flush(out_fd* out) {
#define _outout stdout
    fwrite(out->buf, 1, out->i, _outout);
    out->i = 0;
}
static void out_check(out_fd* out) {
    if (out->i < 0x1800)
        return;
    fprintf(stderr, "Formatted record is too long (0x%x)", out->i);
    out_flush(out);
    exit(EX_DATAERR);
}
static void SAY_S(out_fd* out, const char* str) {
    out_check(out);
    while(*str) out->buf[out->i++] = *(str++);
}
static void SAY_C(out_fd* out, const char chr) {
    out->buf[out->i++] = chr;
}
static void SAY_N(out_fd* out, const char* str, int n) {
    out_check(out);
    for (int i = 0; i < n; i++)
        out->buf[out->i++] = str[i];
}
static void SAY_F(out_fd* out, const char* fmt, ...) {
    out_check(out);
    va_list args;
    va_start(args, fmt);
    out->i += vsprintf(out->buf + out->i, fmt, args);
    va_end  (args);
} 

#define SAY_COL(O,C) if (color_bool) SAY_S(O,C)
#define SAY_COLORED(O,S,C) do { if (color_bool) { SAY_COL(O,C); SAY_S(O,S); SAY_COL(O,ANSI_RESET);} else SAY_S(O,S); } while(0)
static void SAY_ESCAPED(out_fd* out, const char* buf, int size) {
    out_check(out);
    static const char hex_digits[] = "0123456789abcdef";
    const char* ptr = 0;
    for (int i=0; i<size; i++ ) {
        if (isprint(buf[i])) {
            if (ptr == 0) ptr = &buf[i];
        }
        else {
            if (ptr) SAY_N(out, ptr, buf + i - ptr);
                       SAY_C(out, '\\');
            switch(buf[i]) {
            case '\n': SAY_C(out, 'n'); break;
            case '\t': SAY_C(out, 't'); break;
            case '\r': SAY_C(out, 'r'); break;
            case '\0': SAY_C(out, '0'); break;
            default: {
                SAY_C(out, 'x');
                SAY_C(out, hex_digits[(buf[i] >> 4) & 0xf]);
                SAY_C(out, hex_digits[(buf[i]     ) & 0xf]);
            }}}
    }
    if (ptr) SAY_N(out, ptr, buf + size - ptr);
}
static int ends_with_equal(const out_fd* out) {
    return (out->i > 10 && out->buf[out->i-1] == '=');
}

#define COLOR_BOOL parser->color

CREATE_LIST_IMPLEMENTATION(BufferParseContextList, struct trace_parser_buffer_context)
CREATE_LIST_IMPLEMENTATION(RecordsAccumulatorList, struct trace_record_accumulator)

#ifdef ULLONG_MAX
#define MAX_ULLONG	ULLONG_MAX
#else
#define MAX_ULLONG     18446744073709551615ULL
#endif

static int my_strncpy(char* formatted_record, const char* source, int max_size) {
    // Heaven knows why, but this is much faster than strncpy
    int i;
    if (0 >= max_size)
        return 0;
    for (i = 0; source[i] && i < max_size; i++)
        formatted_record[i] = source[i]; 
    return i;

}

static int wait_for_data(trace_parser_t *parser)
{
#ifdef _USE_INOTIFY_
    fd_set read_fdset;
    struct inotify_event event;
    while (TRUE) {
        FD_ZERO(&read_fdset);
        FD_SET(parser->inotify_fd, &read_fdset);

        int rc = select(parser->inotify_fd + 1, &read_fdset, NULL, NULL, NULL);
        if (-1 == rc) {
            return -1;
        }

        rc = read(parser->inotify_fd, &event, sizeof(event));
        if (rc != sizeof(event)) {
            return -1;
        }

        if (event.mask & IN_MODIFY) {
            return 0;
        }
    }
#else
    sleep(1);
    return 0;
#endif
}

static long long get_current_end_offset_from_fd(int fd)
{
    off64_t size;
    size = lseek64(fd, 0, SEEK_END);
    if ((off64_t)-1 == size) {
    	fprintf(stderr, "Failed to obtain end offset for fd %d due to error %s", fd, strerror(errno));
        return -1LL;
    }

    return size;
}

static long long trace_end_offset(trace_parser_t *parser)
{
    off_t new_end = get_current_end_offset_from_fd(parser->file_info.fd);
    if (new_end != parser->file_info.end_offset) {
#ifdef _USE_MREMAP_
        void *new_addr = mremap(parser->file_info.file_base, parser->file_info.end_offset, new_end, MREMAP_MAYMOVE);
        if (!new_addr || MAP_FAILED == new_addr) {
            return -1;
        }
        parser->file_info.end_offset = new_end;
        parser->file_info.file_base = new_addr;
#else
        fprintf(stderr, "Could not increase memory mapping size since this platform doesn't have mremap()\n");
        return -1;
#endif
    }

    return new_end;
}

static void refresh_end_offset(trace_parser_t *parser)
{
    trace_end_offset(parser);
}

static int read_next_record(trace_parser_t *parser, struct trace_record *record)
{
    int rc;
    while (TRUE) {
        if (parser->file_info.current_offset < parser->file_info.end_offset) {
            memcpy(record, (unsigned char *) parser->file_info.file_base + (parser->file_info.current_offset), sizeof(*record));
            parser->file_info.current_offset += sizeof(*record);
            return 0;
        }

        if (parser->wait_for_input) {
            rc = wait_for_data(parser);
            if (0 != rc) {
                return -1;
            } else {
                refresh_end_offset(parser);
                continue;
            }
        } else {
            parser->buffer_dump_context.file_offset++;
            record->rec_type = TRACE_REC_TYPE_END_OF_FILE;
            record->ts = 0;
            return 0;
        }
    }
}


void trace_parser_init(trace_parser_t *parser, trace_parser_event_handler_t event_handler, void *arg, enum trace_input_stream_type stream_type)
{
    memset(parser, 0, sizeof(*parser));
    parser->event_handler = event_handler;
    parser->arg = arg;
    parser->stream_type = stream_type;
    BufferParseContextList__init(&parser->buffer_contexts);
    parser->record_filter.type = TRACE_MATCHER_TRUE;
    parser->show_timestamp = TRUE;
    parser->show_function_name = TRUE;
    RecordsAccumulatorList__init(&parser->records_accumulators);
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

static inline const struct trace_log_descriptor *get_log_descriptor(const struct trace_parser_buffer_context *context, size_t idx)
{
	return (const struct trace_log_descriptor *)((const char *)(context->descriptors) + idx * context->metadata_log_desciptor_size);
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
    	errno = ENOMEM;
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
        my_strncpy(context->name, context->metadata->name, sizeof(context->name) - 1);
        context->name[sizeof(context->name) - 1] = '\0';

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
            errno = ENOMEM;
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

#define TRACE_SEV_X(v, str) [v] = #str,
const char *sev_to_str[] = {
	TRACE_SEVERITY_DEF
};
#undef TRACE_SEV_X

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
            printf("    %s: %d\n", sev_to_str[j], stats->record_count_by_severity[j]);
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
        const int hex_bool = param->flags & TRACE_PARAM_FLAG_HEX || parser->always_hex;
        int put_delimiter = 1; // (param + 1)->flags != 0 ;
        
        if (first) {
            if      (trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY)
                SAY_S  (out, "--> ");
            else if (trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_LEAVE) 
                SAY_S  (out, "<-- ");
        }

        if (param->flags & TRACE_PARAM_FLAG_NAMED_PARAM) {
            if (trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY ||
                parser->show_field_names) {
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
                /*
                  if ((param + 1)->flags != 0)
                  SAY_S  (out, delimiter);
                */
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

                while (1) {
                    unsigned char sl = (*(unsigned char *)pdata);
                    unsigned char len = sl & 0x7f;
                    unsigned char continuation = sl & 0x80;
                    pdata ++;
                    if (param->flags & TRACE_PARAM_FLAG_STR) {
                        SAY_COL(out, CYAN_B);
                        SAY_ESCAPED(out, (const char*) pdata, len);

                        if (!continuation)
                            SAY_S  (out, "\", ");
                    }
                    pdata+= len;

                    if (!continuation)
                        break;
                }
            }
        } break;
        
            /* integer data */
#define GET_PDATA_VAL(TYPE) const TYPE _val = (*(const TYPE*)pdata); pdata += sizeof(_val)

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
                SAY_S  (out, name ? name : "< ?enum>");
            }
        } break;
        
        case TRACE_PARAM_FLAG_NUM_8: {
            if (describe_params) {
                SAY_COLORED(out, "<char>", CYAN_B);
            }
            else {
                GET_PDATA_VAL(unsigned char);
                SAY_COL(out, CYAN_B);
                SAY_F  (out, ( hex_bool ? "0x%x" : "%d" ), _val);
                SAY_COL(out, ANSI_RESET);
            }
        } break;
        
        case TRACE_PARAM_FLAG_NUM_16: {
            if (describe_params) {
                SAY_COLORED(out, "<short>", CYAN_B);
            }
            else {
                GET_PDATA_VAL(unsigned short);
                SAY_COL(out, CYAN_B);
                SAY_F  (out, ( hex_bool ? "0x%x" : "%d" ), _val);
            }
        } break;

        case TRACE_PARAM_FLAG_NUM_32: {
            if (describe_params) {
                SAY_COLORED(out, "<short>", CYAN_B);
            }
            else {
                GET_PDATA_VAL(unsigned int);
                SAY_COL(out, CYAN_B);
                SAY_F  (out, ( hex_bool ? "0x%x" : "%d" ), _val);
            }
        } break;

        case TRACE_PARAM_FLAG_NUM_64: {
            if (describe_params) {
                SAY_COLORED(out, "<long long>", CYAN_B);
            }
            else {
                GET_PDATA_VAL(unsigned long long);
                SAY_COL(out, CYAN_B);
                SAY_F  (out, ( hex_bool ? "0x%llx" : "%lld" ), _val);
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

static const char * severity_to_str(unsigned int sev, int color_bool) {

	static const char* sevs_colored[] = {
        GREY     "----",
        WHITE    "DBG ",
        GREEN_B	 "INFO",
        YELLOW_B "WARN",
        RED_B    "ERR ",
        RED_B    "FATAL"
    };
    static const char* sevs[] = {
        "----",
        "DBG ",
        "INFO",
        "WARN",
        "ERR ",
        "FATAL"
    };

    return
        (sev < TRACE_SEV_FUNC_TRACE || sev > TRACE_SEV_FATAL ) ?
        "???" :
        color_bool ?
        sevs_colored[sev - TRACE_SEV_FUNC_TRACE] :
        sevs        [sev - TRACE_SEV_FUNC_TRACE] ;
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

    if (parser->indent)
        for (int i = 4*MAX(record->nesting, 0); i; i--)
            SAY_C  (out, ' ');

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
        if (parser->stream_type == TRACE_INPUT_STREAM_TYPE_NONSEEKABLE && !(match_record_dump_with_match_expression(&parser->record_filter, buffer_chunk, NULL))) {
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
    const struct trace_record_buffer_dump *buffer_dump = &record->u.buffer_chunk;

    switch ((int) matcher->type) {
        case TRACE_MATCHER_TRUE:
            return TRUE;

        case TRACE_MATCHER_FALSE:
            return FALSE;
    
        case TRACE_MATCHER_NOT:
            return !match_record_dump_with_match_expression(matcher->u.unary_operator_parameters.param, record, buffer_context);

        case TRACE_MATCHER_OR:
            return (match_record_dump_with_match_expression(matcher->u.binary_operator_parameters.a, record, buffer_context) ||
                    match_record_dump_with_match_expression(matcher->u.binary_operator_parameters.b, record, buffer_context));

        case TRACE_MATCHER_AND:
            return (match_record_dump_with_match_expression(matcher->u.binary_operator_parameters.a, record, buffer_context) &&
                    match_record_dump_with_match_expression(matcher->u.binary_operator_parameters.b, record, buffer_context));

            // TODO: Make this more accurate: Consider end range
        case TRACE_MATCHER_TIMERANGE:
            return (buffer_dump->ts > matcher->u.time_range.start);

        case TRACE_MATCHER_PID:
            return record->pid == matcher->u.pid;
    
        case TRACE_MATCHER_SEVERITY:
            return (buffer_dump->severity_type) & (1 << matcher->u.severity);

        case TRACE_MATCHER_SEVERITY_LEVEL:
            return (buffer_dump->severity_type) >= (matcher->u.severity);

        case TRACE_MATCHER_PROCESS_NAME:
            return (buffer_context && strcmp(matcher->u.process_name, buffer_context->name) == 0);

        default:
            return TRUE;
    }
    return TRUE;
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
        
        if (!match_record_dump_with_match_expression(filter, &tmp_record, buffer_context)) {
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

static bool_t record_params_contain_string(
		const struct trace_parser_buffer_context *buffer,
		const struct trace_record_typed *typed_record,
		const char *const_str,
        int exact,
		unsigned int *log_size) {

    unsigned int metadata_index = typed_record->log_id;
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
    if (metadata_index >= buffer->metadata->log_descriptor_count) {
        return FALSE;
    }

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
            value_mask = MAX_ULLONG;
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
            value_mask = MAX_ULLONG;
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

typedef struct {
    int keep_going;
    long long quota;
    int after_count;
    short unsigned int after_count_tid;
} iter_t;

static bool_t match_record_with_match_expression(
		const struct trace_record_matcher_spec_s *matcher,
		const struct trace_parser_buffer_context *buffer,
		const struct trace_record *record,
        iter_t * iter)
{
    unsigned int metadata_index = record->u.typed.log_id;

    if (metadata_index >= buffer->metadata->log_descriptor_count) {
        return FALSE;
    }

    const struct trace_log_descriptor *log_desc = get_log_descriptor(buffer, metadata_index);

    switch (matcher->type) {
    case TRACE_MATCHER_TRUE:
        return TRUE;

    case TRACE_MATCHER_FALSE:
        return FALSE;

    case TRACE_MATCHER_NOT:
        return !match_record_with_match_expression(matcher->u.unary_operator_parameters.param, buffer, record, iter);

    case TRACE_MATCHER_OR:
        return (match_record_with_match_expression(matcher->u.binary_operator_parameters.a, buffer, record, iter) ||
                match_record_with_match_expression(matcher->u.binary_operator_parameters.b, buffer, record, iter));

    case TRACE_MATCHER_AND:
        return (match_record_with_match_expression(matcher->u.binary_operator_parameters.a, buffer, record, iter) &&
                match_record_with_match_expression(matcher->u.binary_operator_parameters.b, buffer, record, iter));

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
                 iter ? (iter->keep_going = FALSE) : FALSE );

    case TRACE_MATCHER_PROCESS_NAME:
        return (0 == strcmp(matcher->u.process_name, buffer->name));

    case TRACE_MATCHER_QUOTA_MAX:
        if(!iter) return TRUE;  /* weird */
        if (iter->quota == 0)
            iter->quota = matcher->u.quota_max + 1;
        return ((0 < --(iter->quota)) ?
                TRUE :
                (iter->keep_going = FALSE));

    case TRACE_MATCHER_FUNCTION_NAME:
        return (log_desc->function &&
                // log_desc->function[0] &&
                0 == strcmp(log_desc->function, matcher->u.function_name));

    default:
        return FALSE;
        
    }

    return FALSE;
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
            int doit = 0;
            if (match_record_with_match_expression(filter, buffer, complete_record, iter)) {
                if (iter) {
                    iter->after_count = 0;
                    iter->after_count_tid = complete_record->tid;
                }
                doit = 1;
            }
            else if (iter &&
                     complete_record->tid == iter->after_count_tid &&
                     parser->after_count > iter->after_count ++)
                doit = 1;
            if (doit) {
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
        my_strncpy(parser->file_info.machine_id, (const char * ) record->u.file_header.machine_id, sizeof(parser->file_info.machine_id));
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
    memset(&tmp_record, 0, sizeof(tmp_record));
    unsigned int i;
    unsigned long long min_ts = MAX_ULLONG;
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
    
    if (min_ts == MAX_ULLONG) {
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
        SAY_S  (out, format_timestamp(MAX(ts, 0), parser->nanoseconds_ts, parser->compact_traces));
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
        int rc = process_next_record_from_file(parser, &parser->record_filter, dumper_event_handler, &dump_context, &iter);
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
    memset(formatted_record, 0, formatted_record_size);
    bool_t exact_size = FALSE;

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
    my_strncpy(formatted_record, out.buf, out.i);
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
    char template[512];
    struct log_stats *stats;
    
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
        my_strncpy(stats->logs[metadata_index].template, template, sizeof(stats->logs[metadata_index].template));
        stats->logs[metadata_index].template[sizeof(stats->logs[metadata_index].template) - 1] = '\0';
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
        int rc = process_next_record_from_file(parser, &parser->record_filter, count_entries, (void *) log_stats_pool, NULL);
        count++;
        if (0 != rc) {
            break;
        }
    }

    dump_stats_pool(log_stats_pool);
    free_stats_pool(log_stats_pool);
    return 0;
}

static int init_inotify(trace_parser_t *parser, const char *filename)
{
#ifdef _USE_INOTIFY_
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
#else
    return -1;
#endif
}

/* Remove rlimits for virtual memory, which could prevent trace_reader from running */
static int remove_limits(void)
{
    static const struct rlimit limit = { RLIM_INFINITY, RLIM_INFINITY };
    return setrlimit(RLIMIT_AS, &limit);
}

static long long aligned_size(long long size)
{
    static long long page_size;
    
    if (!page_size) {
        page_size = sysconf(_SC_PAGE_SIZE);
        if (!page_size || (page_size & (page_size - 1))) {
            /* page size is not a power of two */
            page_size = 4096;
        }
    }

    return (size + page_size - 1) & ~(page_size - 1);
}

static void *mmap_grow(void* addr, long long size, long long new_size)
{
    /* XXX: consider converting to mremap */
    void* new_addr = mmap(NULL, new_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (addr == MAP_FAILED) {
        return new_addr;
    }

    if (addr) {
        memcpy(new_addr, addr, size);
        munmap(addr, size);
    }

    return new_addr;
}

static void *mmap_gzip(int fd, long long *input_size)
{
    gzFile gz;
    unsigned char u[4];
    int len;
    void *addr;
    long long size;
    long long offset;
    long long avail;

    lseek64(fd, -4, SEEK_END);
    len = read(fd, u, sizeof(u));
    if (len != 4) {
        return NULL;
    }

    /* unfortunately gzip's size is 32-bit */
    size = (u[3] << 24) + (u[2] << 16) + (u[1] << 8) + u[0];

    if (size < *input_size) {
        size = (double)*input_size * 1.3;
    }

    lseek64(fd, 0, SEEK_SET);
    gz = gzdopen(fd, "rb");
    if (gz == NULL || gzdirect(gz)) {
        return NULL;
    }

    size = aligned_size(size);

    addr = mmap_grow(NULL, 0, size);
    if (addr == MAP_FAILED) {
        return addr;
    }

    offset = 0;
    avail = size;

    for (;;) {
#define CHUNK 65536
        len = gzread(gz, (char*)addr + offset, MIN(CHUNK, avail));
        if (len < 0) {
            gzclose(gz);
            munmap(addr, size);
            return MAP_FAILED;
        }
        if (len == 0) {
            break;
        }
        offset += len;
        avail -= len;

        // size in trailer doesn't match actual data - more than 4G of input?
        if (avail == 0) {
            long long new_size = aligned_size(size + 0x100000000ll);
            void* new_addr;

            remove_limits();

            new_addr = mmap_grow(addr, size, new_size);

            if (addr == MAP_FAILED) {
                gzclose(gz);
                munmap(addr, size);
                return MAP_FAILED;
            }

            avail = new_size - size;
            addr = new_addr;
            size = new_size;
        }
    }

    gzclose(gz);

    *input_size = offset;

    return addr;
}

static void *mmap_fd(int fd, long long *size)
{
    void *addr = mmap_gzip(fd, size);
    if (addr == MAP_FAILED || addr != NULL) {
        return addr;
    }

    return mmap(NULL, *size, PROT_READ, MAP_SHARED, fd, 0);
}

static int mmap_file(trace_parser_t *parser, const char *filename)
{
    long long size;
    void *addr;
    
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    
    size = get_current_end_offset_from_fd(fd);
    if (size < 0) {
        close(fd);
        return -1;
    }

    addr = mmap_fd(fd, &size);
    if ((MAP_FAILED == addr) && (ENOMEM == errno)) {
    	/* The failure may be due to rlimit for virtual memory set too low, so try to raise it */
    	if (0 != remove_limits()) {
    		return -1;
    	}
    	addr = mmap_fd(fd, &size);
    }

    if (MAP_FAILED == addr) {
        close(fd);
        return -1;
    }

    parser->file_info.fd = fd;
    parser->file_info.file_base = addr;
    parser->file_info.end_offset = size;
    parser->file_info.current_offset = 0;
    return 0;

}

static void unmap_file(trace_parser_t *parser)
{
    munmap(parser->file_info.file_base, parser->file_info.end_offset);
    close(parser->file_info.fd);
    parser->file_info.fd = -1;
}

int TRACE_PARSER__from_file(trace_parser_t *parser, bool_t wait_for_input, const char *filename, trace_parser_event_handler_t event_handler, void *arg)
{
    int rc;
    trace_parser_init(parser, event_handler, arg, TRACE_INPUT_STREAM_TYPE_SEEKABLE_FILE);
    if (wait_for_input) {
        parser->wait_for_input = TRUE;
        if (0 != init_inotify(parser, filename)) {
        	fprintf(stderr, "Failed to set-up inotify"
#ifdef _USE_INOTIFY_
      "because of the following error: %s\n", strerror(errno)
#else
      "because it is unsupported on this platform"
#endif
        	);
            return -1;
        }
    }

    rc = mmap_file(parser, filename);
    if (0 != rc) {
        return -1;
    }

    struct trace_record file_header;

    rc = read_file_header(parser, &file_header);
    if (0 != rc) {
        unmap_file(parser);
        return -1;
    }

    parser->file_info.format_version = file_header.u.file_header.format_version;
    switch (parser->file_info.format_version) {
    case 0xA1:
    	break;

    case 0xA2:
    	break;

    default:
    	errno = EFTYPE;
    	return -1;
    }
    
    my_strncpy(parser->file_info.filename, filename, sizeof(parser->file_info.filename));    
    my_strncpy(parser->file_info.machine_id, (char * ) file_header.u.file_header.machine_id, sizeof(parser->file_info.machine_id));
    return 0;
}

void TRACE_PARSER__fini(trace_parser_t *parser)
{
    if (file_open(parser)) {
        unmap_file(parser);
    }

    free_all_metadata(parser);
}

long long TRACE_PARSER__seek(trace_parser_t *parser, long long offset, int whence)
{
    long long absolute_offset = offset * sizeof(struct trace_record);
    if (parser->stream_type == TRACE_INPUT_STREAM_TYPE_NONSEEKABLE) {
    	errno = EINVAL;
        return -1;
    }
    
    if (!file_open(parser)) {
    	errno = EBADF;
        return -1;
    }

    long long new_offset;
    if (whence == SEEK_SET) {
        new_offset = absolute_offset;
    } else if (whence == SEEK_CUR) {
        new_offset = parser->file_info.current_offset + absolute_offset;
    } else if (whence == SEEK_END) {
        new_offset = parser->file_info.end_offset + absolute_offset;
    } else {
        return -1;
    }

    if (new_offset > parser->file_info.end_offset) {
    	errno = ESPIPE;
        return -1;
    } else {
        parser->buffer_dump_context.file_offset = new_offset / sizeof(struct trace_record);
        parser->file_info.current_offset = new_offset;
        return parser->buffer_dump_context.file_offset;
    }
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
