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

#include "platform.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <limits.h>

#include "trace_macros.h"
#include "trace_lib.h"
#include "trace_user.h"
#include "min_max.h"
#include "trace_metadata_util.h"
#include "trace_clock.h"
#include "trace_proc_util.h"
#include "bool.h"
#include "file_naming.h"
#include "halt.h"

/* Global per process/thread data structures */
struct trace_buffer *current_trace_buffer = NULL;
__thread unsigned short trace_current_nesting;
__thread enum trace_severity trace_thread_severity_threshold = TRACE_SEV_INVALID;


static __thread pid_t tid_cache = 0;

/* Runtime support functions for obtaining information from the system */
static trace_pid_t trace_get_tid(void)
 {
   if (! tid_cache) {
	   tid_cache = syscall(__NR_gettid);
   }
	return (trace_pid_t) tid_cache;
}

static void incalidate_tid_cache(void)
{
    tid_cache = 0;
}

static trace_pid_t trace_get_pid(void)
{
	/* No use doing our own caching for process-id, since glibc already does it for us in a fork-safe way (see the man page) */
    return (trace_pid_t) getpid();
}


static struct trace_runtime_control runtime_control =
{
	TRACE_SEV_INVALID,
	{0, 0},
	NULL,
	64,
	3
};

const struct trace_runtime_control *const p_trace_runtime_control = &runtime_control;

enum trace_severity trace_runtime_control_set_default_min_sev(enum trace_severity sev)
{
    enum trace_severity prev = runtime_control.default_min_sev;
	runtime_control.default_min_sev = sev;
	return prev;
}

int trace_runtime_control_set_sev_threshold_for_subsystem(int subsystem_id, enum trace_severity sev)
{
	if ((NULL == runtime_control.thresholds) ||
		(subsystem_id < runtime_control.subsystem_range[0]) ||
		(subsystem_id > runtime_control.subsystem_range[1])) {
		errno = EINVAL;
		return -1;
	}

	runtime_control.thresholds[subsystem_id - runtime_control.subsystem_range[0]] = sev;
	return 0;
}

static void trace_runtime_control_free_thresholds(void) {
    if (NULL != runtime_control.thresholds) {
    	void *thresholds = runtime_control.thresholds;
    	runtime_control.thresholds = NULL;
    	runtime_control.subsystem_range[0] = runtime_control.subsystem_range[1] = 0;
    	free(thresholds);
    }
}

int trace_runtime_control_set_subsystem_range(int low, int high)
{
	if (high < low) {
		errno = EINVAL;
		return -1;
	}

	trace_runtime_control_free_thresholds();

	runtime_control.subsystem_range[0] = low;
	runtime_control.subsystem_range[1] = high;

	runtime_control.thresholds = calloc(high - low + 1, sizeof(runtime_control.thresholds[0]));
	if (NULL == runtime_control.thresholds) {
		return -1;
	}

	return 0;
}

static __thread struct trace_internal_err_info internal_err_info = {0, 0, 0};

const struct trace_internal_err_info *trace_internal_err_get_last(void)
{
    return &internal_err_info;
}

void trace_internal_err_clear(void)
{
    memset(&internal_err_info, 0, sizeof(internal_err_info));
}

int trace_internal_err_clear_errno(void)
{
    const int saved_errno = internal_err_info.err_num;
    internal_err_info.err_num = 0;
    return saved_errno;
}

void trace_internal_err_record_if_necessary(int saved_errno, const struct trace_record *header)
{
    if (__builtin_expect(0 == internal_err_info.err_num, TRUE)) {
        internal_err_info.err_num = saved_errno;
    }
    else {
        if (NULL != header) {
            internal_err_info.ts = header->ts;
            internal_err_info.log_id = (header->rec_type == TRACE_REC_TYPE_TYPED) ? header->u.typed.log_id : (trace_log_id_t) -1;
        }
        else {
            internal_err_info.ts = 0;
            internal_err_info.log_id = 0;
        }
    }
}

/* Runtime support functions called when writing traces to shared-memory */

static inline void set_current_trace_buffer_ptr(struct trace_buffer *trace_buffer_ptr)
{
    current_trace_buffer = trace_buffer_ptr;
}

int trace_runtime_control_configure_buffer_allocation(unsigned initial_records_per_trace, unsigned records_array_increase_factor)
{
	if ((initial_records_per_trace < 1) || (records_array_increase_factor < 2)) {
	    internal_err_info.err_num = EINVAL;
		return -1;
	}

	runtime_control.initial_records_per_trace     = initial_records_per_trace;
	runtime_control.records_array_increase_factor = records_array_increase_factor;
	return 0;
}

static struct trace_records *trace_get_records(enum trace_severity severity)
{
	TRACE_ASSERT(TRACE_SEV_INVALID != severity);

	switch ((int)severity) {
	case TRACE_SEV_FUNC_TRACE:
		return &current_trace_buffer->u.records._funcs;

	case TRACE_SEV_DEBUG:
		return &current_trace_buffer->u.records._debug;

	default:
		return &current_trace_buffer->u.records._other;
	}
}

static inline trace_generation_t trace_get_generation(trace_record_counter_t record_num, const struct trace_records_immutable_metadata *imutab)
{
	return (trace_generation_t)(record_num >> imutab->max_records_shift);
}

static inline int trace_compare_generation(trace_generation_t a, trace_generation_t b)
{
#ifndef _LP64
#warning "This function was tested with sizeof(trace_generation_t)=4, sizeof(trace_atomic_t)=8, if this is not true please test it!"
#endif

	enum thresholds {
		GEN_LOW  = 0x4U << (8 * sizeof(trace_generation_t) - 4),
		GEN_HIGH = 0xcU << (8 * sizeof(trace_generation_t) - 4),
	};

	if (a >= GEN_HIGH   &&  b < GEN_LOW)
		return 1;
	if (b > a)
		return 1;
	if (b < a)
		return -1;
	return 0;
}

static inline unsigned bytes_left_in_buf(const struct trace_record *records, unsigned rec_idx, const unsigned char *typed_buf)
{
	const unsigned bytes_left = records[rec_idx].u.payload + TRACE_RECORD_PAYLOAD_SIZE - typed_buf;
	TRACE_ASSERT(bytes_left <= TRACE_RECORD_PAYLOAD_SIZE);  /* Check for typed_buf pointing outside the buffer */
	return bytes_left;
}

unsigned char *trace_copy_vstr_to_records(struct trace_record **records, unsigned *rec_idx, unsigned *records_array_len, unsigned char *typed_buf, const char *src)
{
	const unsigned char CONTINUATION_MASK = 0x80;
	unsigned bytes_left = bytes_left_in_buf(*records, *rec_idx, typed_buf);

	do {
		if (0 == bytes_left) {
			trace_advance_record_array(records, rec_idx, records_array_len);
			typed_buf = (*records)[*rec_idx].u.payload;
			bytes_left = TRACE_RECORD_PAYLOAD_SIZE;
		}

		unsigned copy_size;
		const char *end = memchr(src, '\0', bytes_left);
		if (NULL != end) { /* The remaining length of the string can fit in the buffer */
			copy_size = end - src;
			TRACE_ASSERT(copy_size < bytes_left);
			typed_buf[0] = 0;
		}
		else {
			copy_size = bytes_left - 1;
			typed_buf[0] = CONTINUATION_MASK;
			TRACE_ASSERT(src[copy_size]);
		}

		TRACE_ASSERT(copy_size < CONTINUATION_MASK);

		typed_buf[0] |= copy_size;
		++typed_buf;
		memcpy(typed_buf, src, copy_size);

		src += copy_size;
		typed_buf += copy_size;
		bytes_left -= (1 + copy_size);

	} while(*src);

	/* Make sure we're not allocating a new record needlessly */
	TRACE_ASSERT(bytes_left < TRACE_RECORD_PAYLOAD_SIZE);

	return typed_buf;
}

unsigned char *trace_copy_scalar_to_records(struct trace_record **records, unsigned *rec_idx, unsigned *records_array_len, unsigned char *typed_buf, const unsigned char *src, unsigned len)
{
    TRACE_ASSERT(len < TRACE_RECORD_PAYLOAD_SIZE);

    unsigned bytes_left = bytes_left_in_buf(*records, *rec_idx, typed_buf);
    const unsigned copy_size = MIN(bytes_left, len);
    memcpy(typed_buf, src, copy_size);

    if (copy_size < len) {
        trace_advance_record_array(records, rec_idx, records_array_len);
        const unsigned second_copy_size = len - copy_size;
        unsigned char *const second_copy_start = (*records)[*rec_idx].u.payload;

        memcpy(second_copy_start, src + copy_size, second_copy_size);
        typed_buf = second_copy_start + second_copy_size;
    }
    else {
        typed_buf += len;
    }

    return typed_buf;
}

void trace_clear_record_remainder(struct trace_record *records, unsigned rec_idx, unsigned char *typed_buf)
{
    memset(typed_buf, TRACE_UNUSED_SPACE_FILL_VALUE, bytes_left_in_buf(records, rec_idx, typed_buf));
}

static void update_last_committed_record(struct trace_records *records, trace_record_counter_t new_index)
{
	trace_record_counter_t expected_value;
	trace_record_counter_t found_value = records->mutab.last_committed_record;

	/* Update records->mutab.last_committed_record to the index of the current record, taking care not to overwrite a larger value.
	 * It's possible that another thread has increased records->mutab.last_committed_record between the last statement and this point so
	 * occasionally we might have to repeat this more than once.  */
	do {
		expected_value = found_value;

		/* Forego the update if another thread has committed a later record */
#ifndef _LP64
#warning "The comparison below might cause anomalous behavior due to counter wrap-around on 32-bit platforms, please verify and test."
#endif
		if ((expected_value > new_index) && (expected_value < -1UL)) {
			break;
		}

		found_value = __sync_val_compare_and_swap(
				&records->mutab.last_committed_record,
				expected_value,
				new_index);

		/* Make absolutely sure that no other thread has committed the same record that we were working on */
		TRACE_ASSERT(new_index != found_value);
	} while (found_value != expected_value);
}


void trace_commit_records(
		struct trace_record *source_records,
		size_t n_records,
		enum trace_severity severity)
{
	TRACE_ASSERT(n_records > 0);
	TRACE_ASSERT(NULL != source_records);

	const trace_ts_t  ts  = trace_get_nsec();
	const trace_pid_t pid = trace_get_pid();
	const trace_pid_t tid = trace_get_tid();

	struct trace_records *const records = trace_get_records(severity);
	TRACE_ASSERT((1U << severity) & records->imutab.severity_type);


	/* TODO: Consider allowing an option for lossless tracing. */
	const trace_record_counter_t base_index = __sync_fetch_and_add(&records->mutab.current_record, n_records);

	size_t i;
	for (i = 0; i < n_records; i++) {
		source_records[i].termination = (i > 0) ? 0 : TRACE_TERMINATION_FIRST;
		if (n_records - 1 == i) {
			source_records[i].termination |= TRACE_TERMINATION_LAST;
		}
		/* TODO: This could be a good place to pre-fetch the next trace record using e.g. __builtin_prefetch */
		source_records[i].ts = ts;
		source_records[i].pid = pid;
		source_records[i].tid = tid;
		source_records[i].severity = severity;
		source_records[i].rec_type = TRACE_REC_TYPE_TYPED;

		const trace_record_counter_t record_index = base_index + i;
		source_records[i].generation = trace_get_generation(record_index, &records->imutab);
		struct trace_record *target = records->records + (record_index & records->imutab.max_records_mask);

		/* TODO: Consider writing a custom copy function using _mm_stream_si128 or similar. This will avoid needless thrashing of the CPU cache on writes. */
		memcpy(target, source_records + i, sizeof(*target));
	}

	trace_free_records_array();

	/* Check that it is at least possible that all the records that were in the process of being written at the time were started have been written by now.
	 * Note that the condition below doesn't guarantee that they have in fact been written. An algorithm that can ascertain that remains to be developed. */
	const trace_record_counter_t records_written = __sync_fetch_and_add(&records->mutab.num_records_written, n_records);
	if (records_written >= base_index) {
		update_last_committed_record(records, base_index + n_records - 1);
	}
}

/* Functions for managing memory allocations on the heap while writing traces. This is seldom required, only when the amount of memory allocated on the stack in order to produce the
 * trace is insufficient */

static __thread struct trace_record *trace_records_dynamic_array = NULL;

struct trace_record *trace_realloc_records_array(struct trace_record *const records, unsigned int *n_records)
{
	assert(runtime_control.records_array_increase_factor > 1);
	if (NULL == n_records) {
	    internal_err_info.err_num = EFAULT;
		return NULL;
	}

	/* Verify that records is either a pointer obtained through a previous call to this function or NULL */
	const bool_t records_valid = (NULL == trace_records_dynamic_array) || (records == trace_records_dynamic_array);
	if ((*n_records < 1) || ! records_valid)  {
	    internal_err_info.err_num = EINVAL;
		return NULL;
	}

	const size_t old_size = TRACE_RECORD_SIZE * *n_records;
	const size_t new_size = old_size * runtime_control.records_array_increase_factor;
	struct trace_record *new_records = realloc(trace_records_dynamic_array, new_size);

	if (NULL == new_records) {
		/* The old array could not be increased, but it is still valid */
		return (NULL != records) ? records : trace_records_dynamic_array;
	}

	if ((NULL != records) && (NULL == trace_records_dynamic_array)) {  /* The original data is in an array allocated on the stack */
		memcpy(new_records, records, old_size);
	}
	*n_records = new_size / TRACE_RECORD_SIZE;
	trace_records_dynamic_array = new_records;
	return new_records;
}

void trace_free_records_array()
{
	if (NULL != trace_records_dynamic_array) {
		free(trace_records_dynamic_array);
		trace_records_dynamic_array = NULL;
	}
}

/* Functions for creating the per traced process shared-memory areas at runtime. */

#define ALLOC_STRING(dest, source)                      \
    do {                                                \
    const size_t str_size = __builtin_strlen(source) + 1;   \
    __builtin_memcpy(*string_table, source, str_size); \
    dest = *string_table;                               \
    *string_table += str_size;      \
    } while(0);                                              

/* Data structures supporting the initialization of the trace subsystem */
static char shm_dir_path[0x100] = "";


/* Routines for initializing the data structures that support tracing inside the traced process. */


static bool_t is_same_str(const char *s1, const char *s2) {
	if ((NULL ==  s1) || (NULL == s2)) {
		return FALSE;
	}

	return 0 == __builtin_strcmp(s1, s2);
}

static void copy_log_params_to_allocated_buffer(struct trace_log_descriptor *log_desc, struct trace_param_descriptor **params,
                                                char **string_table)
{
	const struct trace_param_descriptor *param = log_desc->params;

    while (param->flags != 0) {
        __builtin_memcpy(*params, param, sizeof(struct trace_param_descriptor));

        if (param->str) {
            ALLOC_STRING((*params)->str, param->str);
        }

        if (param->param_name) {
            ALLOC_STRING((*params)->param_name, param->param_name);
        }

        (*params)++;
        param++;
    }

    // Copy the sentinel param
    __builtin_memcpy(*params, param, sizeof(struct trace_param_descriptor));
    (*params)++;
}


static void copy_log_descriptors_to_allocated_buffer(unsigned int log_descriptor_count, struct trace_log_descriptor *log_desc, struct trace_param_descriptor *params,
                                                     char **string_table)
    
{
#if TRACE_FORMAT_VERSION >= TRACE_FORMAT_VERSION_INTRODUCED_FILE_FUNCTION_METADATA
    const char *last_file = NULL;
    const char *last_function = NULL;
#endif

    /* NOTE: The allocations performed in this function should not exceed the size computed in static_log_alloc_size. Care should be taken to keep the algorithms
     * use here and there compatible. */

    unsigned int i;
    for (i = 0; i < log_descriptor_count; i++) {
        struct trace_log_descriptor *orig_log_desc = __static_log_information_start + i;
        memcpy(log_desc, orig_log_desc, sizeof(*log_desc));

#if TRACE_FORMAT_VERSION >= TRACE_FORMAT_VERSION_INTRODUCED_FILE_FUNCTION_METADATA
        if (is_same_str(last_file, orig_log_desc->file)) {
        	log_desc->file = last_file;
        }
        else {
        	ALLOC_STRING(last_file, orig_log_desc->file);
        	log_desc->file = last_file;
        }

        if (is_same_str(last_function, orig_log_desc->function)) {
            log_desc->function = last_function;
        }
        else {
			ALLOC_STRING(last_function, orig_log_desc->function);
			log_desc->function = last_function;
		}
#endif

        log_desc->params = params;
        copy_log_params_to_allocated_buffer(orig_log_desc, &params, string_table);
        log_desc++;
    }
}

static void copy_enum_values_to_allocated_buffer(const struct trace_type_definition *type_definition, struct trace_enum_value **enum_values,
                                                 char **string_table)
{
    struct trace_enum_value *enum_value = type_definition->enum_values;
    while (enum_value->name != NULL) {
        memcpy(*enum_values, enum_value, sizeof(*enum_value));
        ALLOC_STRING((*enum_values)->name, enum_value->name);
        (*enum_values)++;
        enum_value++;
    }

    // Copy the sentinel enum value
    memcpy(*enum_values, enum_value, sizeof(*enum_value));
    (*enum_values)++;
}

static void copy_type_definitions_to_allocated_buffer(struct trace_type_definition *type_definition, struct trace_enum_value *enum_values,
                                                      char **string_table)
{
    const struct trace_type_definition *type = __type_information_start;
    while (type) {
        memcpy(type_definition, type, sizeof(*type_definition));
        ALLOC_STRING(type_definition->type_name, type->type_name);
        type_definition->enum_values = enum_values;
        switch (type->type_id) {
        case TRACE_TYPE_ID_ENUM:
            copy_enum_values_to_allocated_buffer(type, &enum_values, string_table);
            break;
        case TRACE_TYPE_ID_RECORD:
            break;
        case TRACE_TYPE_ID_TYPEDEF:
            break;
        default:
            break;
        }
        
        type_definition++;
        type = *((struct trace_type_definition **) ((char *) type + sizeof(*type)));
    }
}

static void copy_metadata_to_allocated_buffer(unsigned int log_descriptor_count, struct trace_log_descriptor *log_desc, struct trace_param_descriptor *params,
                                              struct trace_type_definition *type_definition, struct trace_enum_value *enum_values,
                                              char **string_table)
{
    copy_log_descriptors_to_allocated_buffer(log_descriptor_count, log_desc, params, string_table);
    copy_type_definitions_to_allocated_buffer(type_definition, enum_values, string_table);
}

static void *set_size_and_mmap_shm(size_t length, int shm_fd)
{
    if (ftruncate(shm_fd, length) < 0) {
        return MAP_FAILED;
    }

    return mmap(NULL, length, PROT_WRITE, MAP_SHARED, shm_fd, 0);
}

static void copy_log_section_shared_area(int shm_fd, const char *buffer_name,
                                         unsigned int log_descriptor_count,
                                         unsigned int log_param_count,
                                         unsigned int type_definition_count,
                                         unsigned int enum_value_count,
                                         unsigned int alloc_size)
{
    void *const mapped_addr = set_size_and_mmap_shm(alloc_size, shm_fd);
    TRACE_ASSERT((MAP_FAILED != mapped_addr) && (NULL != mapped_addr));
    struct trace_metadata_region *metadata_region = (struct trace_metadata_region *) mapped_addr;
    TRACE_ASSERT((NULL == metadata_region->base_address) && ('\0' == metadata_region->name[0]));

    struct trace_log_descriptor *log_desc = (struct trace_log_descriptor *) metadata_region->data;
    struct trace_type_definition *type_definition = (struct trace_type_definition *)((char *) log_desc + (sizeof(struct trace_log_descriptor) * log_descriptor_count));
    struct trace_param_descriptor *params = (struct trace_param_descriptor *)((char *) type_definition + (type_definition_count * sizeof(struct trace_type_definition)));
    struct trace_enum_value *enum_values = (struct trace_enum_value *) ((char *) params + (log_param_count * sizeof(struct trace_param_descriptor)));
    char *string_table = (char *) enum_values + (enum_value_count * sizeof(struct trace_enum_value));

    metadata_region->log_descriptor_count = log_descriptor_count;
    metadata_region->type_definition_count = type_definition_count;
    copy_metadata_to_allocated_buffer(log_descriptor_count, log_desc, params,
                                      type_definition, enum_values,
                                      &string_table);

    strncpy(metadata_region->name, buffer_name, sizeof(metadata_region->name));
    metadata_region->name[sizeof(metadata_region->name) - 1] = '\0';
    metadata_region->base_address = mapped_addr;
    TRACE_ASSERT(0 == munmap(mapped_addr, alloc_size));
}

static void param_alloc_size(const struct trace_param_descriptor *params, unsigned int *alloc_size, unsigned int *total_params)
{
    while (params->flags != 0) {
        if (params->str) {
            int len = strlen(params->str) + 1;
            *alloc_size += len;
        }

        if (params->param_name) {
            int len = strlen(params->param_name) + 1;
            *alloc_size += len;
        }

        *alloc_size += sizeof(*params);
        (*total_params)++;
        params++;
    }

    // Account for the sentinel param
    *alloc_size += sizeof(*params);
    (*total_params)++;
}

static void enum_values_alloc_size(struct trace_enum_value *values, unsigned int *enum_value_count,
                                       unsigned int *alloc_size)
{
    while (values->name != NULL) {
        *alloc_size += sizeof(*values);
        *alloc_size += strlen(values->name) + 1;
        (*enum_value_count)++;
        values++;
    }

    // Account for senitnel
    (*enum_value_count)++;
    *alloc_size += sizeof(*values);
}

static void type_definition_alloc_size(struct trace_type_definition *type, unsigned int *enum_value_count,
                                       unsigned int *alloc_size)
{
    *alloc_size += sizeof(*type);
    *alloc_size += strlen(type->type_name) + 1;
    switch (type->type_id) {
    case TRACE_TYPE_ID_ENUM:
        enum_values_alloc_size(type->enum_values, enum_value_count, alloc_size);
        break;
    case TRACE_TYPE_ID_RECORD:
        break;
    case TRACE_TYPE_ID_TYPEDEF:
        break;
    default:
        break;
    }
}
    
static void type_alloc_size(struct trace_type_definition *type_start, unsigned int *type_definition_count, unsigned int *enum_value_count,
                            unsigned int *alloc_size)
{
    *type_definition_count = 0;
    *enum_value_count = 0;
    
    struct trace_type_definition *type = (struct trace_type_definition *) type_start;
    while (type) {
        (*type_definition_count)++;
        type_definition_alloc_size(type, enum_value_count, alloc_size);
        type = *((struct trace_type_definition **) ((char *) type + sizeof(*type_start)));
    }
}

static void static_log_alloc_size(unsigned int log_descriptor_count, unsigned int *total_params,
                                  unsigned int *type_definition_count, unsigned int *enum_value_count,
                                  unsigned int *alloc_size)
{
    unsigned int i;
    *alloc_size = 0;
    *total_params = 0;

    const char *latest_file = NULL;
    const char *latest_function = NULL;

    for (i = 0; i < log_descriptor_count; i++) {
        const struct trace_log_descriptor *element = __static_log_information_start + i;
        *alloc_size += sizeof(*element);
        param_alloc_size(element->params, alloc_size, total_params);

        if (!is_same_str(element->file, latest_file)) {
        	latest_file = element->file;
        	*alloc_size += strlen(latest_file) + 1;
        }

        if (!is_same_str(element->function, latest_function)) {
        	latest_function = element->function;
			*alloc_size += strlen(latest_function) + 1;
		}
    }
    
    type_alloc_size(__type_information_start, type_definition_count, enum_value_count, alloc_size);
}

static int open_trace_shm(const char *shm_name)
{
    return shm_open(shm_name, O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
}

static void map_static_log_data(const char *buffer_name)
{
    trace_shm_name_buf shm_name;
    unsigned long log_descriptor_count = __static_log_information_end - __static_log_information_start;
    unsigned int alloc_size;
    unsigned int total_log_descriptor_params;
    unsigned int type_definition_count;
    unsigned int enum_value_count;

    TRACE_ASSERT(trace_generate_shm_name(shm_name, getpid(), TRACE_SHM_TYPE_STATIC, FALSE) > 0);
    const int shm_fd = open_trace_shm(shm_name);
    TRACE_ASSERT(shm_fd >= 0);
    
    static_log_alloc_size(log_descriptor_count, &total_log_descriptor_params, &type_definition_count, &enum_value_count, &alloc_size);
    alloc_size = (alloc_size + TRACE_RECORD_SIZE - 1) & ~(TRACE_RECORD_SIZE - 1);
    copy_log_section_shared_area(shm_fd, buffer_name, log_descriptor_count, total_log_descriptor_params,
                                 type_definition_count, enum_value_count,
                                 sizeof(struct trace_metadata_region) + alloc_size);
    TRACE_ASSERT(0 == close(shm_fd));
}

static unsigned get_nearest_power_of_2(unsigned long n)
{
    /* TODO: Consider using the intrinsic __builtin_clz here. */
	unsigned p;
	for (p = 0; n > 1; n >>=1, p++)
		;

	return p;
}

static void init_records_immutable_data(struct trace_records *records, unsigned long num_records, int severity_type)
{
	records->imutab.max_records_shift = get_nearest_power_of_2(num_records);

	records->imutab.max_records = 1U << records->imutab.max_records_shift;
	records->imutab.max_records_mask = records->imutab.max_records - 1U;

	TRACE_ASSERT(records->imutab.max_records > 1U);

    records->imutab.severity_type = severity_type;
    TRACE_ASSERT(0 != records->imutab.severity_type);
}

static void init_record_mutable_data(struct trace_records *recs)
{
	recs->mutab.current_record = 0;
	recs->mutab.num_records_written = 0;
	recs->mutab.last_committed_record = -1UL;
	memset(recs->records, TRACE_SEV_INVALID, sizeof(recs->records[0]));
	TRACE_ASSERT(recs->imutab.max_records > 0);
	memset(recs->records + recs->imutab.max_records - 1, TRACE_SEV_INVALID, sizeof(recs->records[0]));
}

static void init_records_metadata(void)
{

#define ALL_SEVS_ABOVE(sev) ((1 << (TRACE_SEV__MAX + 1))) - (1 << (sev + 1))

    init_records_immutable_data(&current_trace_buffer->u.records._other, TRACE_RECORD_BUFFER_RECS, ALL_SEVS_ABOVE(TRACE_SEV_DEBUG));
    init_records_immutable_data(&current_trace_buffer->u.records._debug, TRACE_RECORD_BUFFER_RECS, (1 << TRACE_SEV_DEBUG));
	init_records_immutable_data(&current_trace_buffer->u.records._funcs, TRACE_RECORD_BUFFER_FUNCS_RECS, (1 << TRACE_SEV_FUNC_TRACE));

 	init_record_mutable_data(&(current_trace_buffer->u.records._other));
	init_record_mutable_data(&(current_trace_buffer->u.records._debug));
	init_record_mutable_data(&(current_trace_buffer->u.records._funcs));
}

static size_t calc_dymanic_buf_size(void)
{
    return sizeof(struct trace_buffer)
            - TRACE_RECORD_BUFFER_RECS       * sizeof(struct trace_record)
            + TRACE_RECORD_BUFFER_FUNCS_RECS * sizeof(struct trace_record);
}

static int init_shm_dir_from_fd(int shm_fd)
{
    char shm_path[PATH_MAX];
    if (trace_get_fd_path(shm_fd, shm_path, sizeof(shm_path)) < 0) {
        return -1;
    }

    shm_dir_path[sizeof(shm_dir_path) - 1] = '\0';
    strncpy(shm_dir_path, dirname(shm_path), sizeof(shm_dir_path));
    if ('\0' != shm_dir_path[sizeof(shm_dir_path) - 1]) {
        shm_dir_path[sizeof(shm_dir_path) - 1] = '\0';
        errno = ENAMETOOLONG;
        return -1;
    }

    return 0;
}

static int perform_2_path_operation_in_shm_dir(
        int (*func)(const char *p1, const char *p2),
        const char *file1,
        const char *file2)
{
    const size_t len_dir = strlen(shm_dir_path);

#define init_path(n) \
    const size_t len##n = strlen(file##n); \
    char *const path##n = alloca(len_dir + len##n + 10); \
    sprintf(path##n, "%s/%s", shm_dir_path, file##n);

    init_path(1);
    init_path(2);

#undef init_path

    return func(path1, path2);
}

static int rename_shm(const char *old_name, const char *new_name) {
    if (trace_delete_shm_if_necessary(new_name) < 0) {
        return -1;
    }

    return perform_2_path_operation_in_shm_dir(rename, old_name, new_name);
}

static int duplicate_shm(const char *orig_name, const char *duplicate_name)
{
    if (trace_delete_shm_if_necessary(duplicate_name) < 0) {
        return -1;
    }

    return perform_2_path_operation_in_shm_dir(link, orig_name, duplicate_name);
}

static int map_dynamic_log_buffers(void)
{
    trace_shm_name_buf shm_tmp_name;
    TRACE_ASSERT(trace_generate_shm_name(shm_tmp_name, getpid(), TRACE_SHM_TYPE_DYNAMIC, TRUE) > 0);

    const int shm_fd = open_trace_shm(shm_tmp_name);
    if (shm_fd < 0) {
        return shm_fd;
    }

    if (init_shm_dir_from_fd(shm_fd) < 0) {
#ifdef SHM_DIR
        strcpy(shm_dir_path, SHM_DIR);  /* Hard-coded default. */
#else
        close(shm_fd);
        return -1;
#endif
    }

    const size_t buf_size = calc_dymanic_buf_size();
    void *const mapped_addr = set_size_and_mmap_shm(buf_size, shm_fd);

    if ((0 != close(shm_fd)) || (MAP_FAILED == mapped_addr) || (NULL == mapped_addr)) {
        goto free_shm;
    }

#ifdef MADV_DONTFORK
    if (0 != madvise(mapped_addr, buf_size, MADV_DONTFORK)) {
        goto free_shm;
    }
#else
#warning "MADV_DONTFORK is not supported, weird behavior could result during forks."
#endif

    set_current_trace_buffer_ptr((struct trace_buffer *)mapped_addr);
    init_records_metadata();

    /* In order to avoid a possible race condition of the dumper accessing the shared-memory area before it is fully initialized, we only rename it
     * to the name the dumper expects after completing its initialization. */
    trace_shm_name_buf shm_name;
    TRACE_ASSERT(trace_generate_shm_name(shm_name, getpid(), TRACE_SHM_TYPE_DYNAMIC, FALSE) > 0);
    if (rename_shm(shm_tmp_name, shm_name) < 0) {
        goto free_shm;
    }

    return 0;


free_shm:
    if (MAP_FAILED != mapped_addr) {
        munmap(mapped_addr, buf_size);
    }
    trace_delete_shm_if_necessary(shm_tmp_name);
    TRACE_ASSERT(0 != errno);
    return -1;
}

static int unmap_buffer_if_necessary()
{
    if (NULL != current_trace_buffer) {
        const int saved_errno = errno;

        /* Try to unmap the pages. The unmap could legitimately fail if the current process is the result of a fork(), since the mapping has MADV_DONTFORK set */
        if (munmap(current_trace_buffer, calc_dymanic_buf_size()) < 0) {
            if ((EINVAL != errno) && (EFAULT != errno)) {
                return -1;
            }

            errno = saved_errno;
        }

        current_trace_buffer = NULL;
    }

    TRACE_ASSERT(NULL == current_trace_buffer);
    return 0;
}

int TRACE__register_buffer(const char *buffer_name)
{
    if (unmap_buffer_if_necessary() < 0) {
        return -1;
    }

    map_static_log_data(buffer_name);
    const int rc = map_dynamic_log_buffers();
    if (rc < 0) {
        trace_shm_name_buf shm_name;
        TRACE_ASSERT(trace_generate_shm_name(shm_name, getpid(), TRACE_SHM_TYPE_STATIC, FALSE) > 0);
        trace_delete_shm_if_necessary(shm_name);
    }

    return rc;
}

int trace_init(const struct trace_init_params *conf __attribute__((unused)))
{
    char buffer_name[NAME_MAX];
    if (trace_get_current_exec_basename(buffer_name, sizeof(buffer_name)) < 0) {
        return -1;
    }

    return TRACE__register_buffer(buffer_name);
}

/* Place TRACE__implicit_init in the constructors section, which causes it to be executed before main() */
static int TRACE__implicit_init(void) __attribute__((constructor));

static int TRACE__implicit_init(void) {
    assert(0 == trace_init(NULL));
    return 0;
}

int trace_finalize(void)
{
    int rc = 0;
    if (NULL != current_trace_buffer) {
        void *const saved_buffer = current_trace_buffer;
        current_trace_buffer = NULL;
        rc = munmap(saved_buffer, calc_dymanic_buf_size());
    }

    trace_runtime_control_free_thresholds();
    rc |= delete_shm_files(getpid());
    return rc;
}

void TRACE__fini(void)
{
    TRACE_ASSERT(0 == trace_finalize());
}

static int child_proc_init(void)
{
    incalidate_tid_cache();

    trace_shm_name_buf parent_static_shm_name;
    TRACE_ASSERT(trace_generate_shm_name(parent_static_shm_name, getppid(), TRACE_SHM_TYPE_STATIC, FALSE) > 0);

    trace_shm_name_buf static_shm_name;
    TRACE_ASSERT(trace_generate_shm_name(static_shm_name, getpid(), TRACE_SHM_TYPE_STATIC, FALSE) > 0);

    if (duplicate_shm(parent_static_shm_name, static_shm_name) < 0) {
        return -1;
    }

    if (map_dynamic_log_buffers() < 0) {
        trace_delete_shm_if_necessary(static_shm_name);
        return -1;
    }

    return 0;
}

pid_t trace_fork(void)
{
    return trace_fork_with_child_init(child_proc_init, delete_shm_files);
}


