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

#include "macros.h"
#include "trace_lib.h"
#include "trace_user.h"
#include "trace_metadata_util.h"
#include "bool.h"
#include "halt.h"

/* Global per process/thread data structures */
struct trace_buffer *current_trace_buffer = NULL;
__thread unsigned short trace_current_nesting;
__thread enum trace_severity trace_thread_severity_threshold = TRACE_SEV_INVALID;


/* Runtime support functions for obtaining information from the system */
static trace_pid_t trace_get_tid(void)
 {
   static __thread pid_t tid_cache = 0;
   if (! tid_cache) {
	   tid_cache = syscall(__NR_gettid);
   }
	return (trace_pid_t) tid_cache;
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


/* Runtime support functions called when writing traces to shared-memory */

static inline void set_current_trace_buffer_ptr(struct trace_buffer *trace_buffer_ptr)
{
    current_trace_buffer = trace_buffer_ptr;
}

int trace_runtime_control_configure_buffer_allocation(unsigned initial_records_per_trace, unsigned records_array_increase_factor)
{
	if ((initial_records_per_trace < 1) || (records_array_increase_factor < 2)) {
		errno = EINVAL;
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


static void update_last_committed_record(struct trace_records *records, trace_record_counter_t new_index)
{
	__sync_synchronize();

	trace_record_counter_t expected_value;
	trace_record_counter_t found_value;

	/* Update records->mutab.last_committed_record to the index of the current record, taking care not to overwrite a larger value.
	 * It's possible that another thread has increased records->mutab.last_committed_record between the last statement and this point so
	 * occasionally we might have to repeat this more than once.  */
	do {
		expected_value = records->mutab.last_committed_record;

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
		TRACE_ASSERT((new_index != found_value) || (0 == new_index));
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

	update_last_committed_record(records, base_index + n_records - 1);
}

struct trace_record *trace_realloc_records_array(struct trace_record *records, unsigned int* n_records, const struct trace_record *initial_array)
{
	assert(runtime_control.records_array_increase_factor > 1);
	if ((NULL == records) || (NULL == n_records)) {
		errno = EFAULT;
		return NULL;
	}

	if (*n_records < 1) {
		errno = EINVAL;
		return NULL;
	}

	const size_t old_size = TRACE_RECORD_SIZE * *n_records;
	const size_t new_size = old_size * runtime_control.records_array_increase_factor;
	struct trace_record *new_records = NULL;

	if (records == initial_array) {  /* The data is in an array allocated on the stack */
		new_records = malloc(new_size);
		if (NULL != new_records) {
			memcpy(new_records, records, old_size);
		}
	}
	else {
		new_records = realloc(records, new_size);
	}

	if (NULL != new_records) {
		*n_records = new_size;
		return new_records;
	}
	else {
		return records;
	}
}

void trace_free_records_array(struct trace_record *records, const struct trace_record *initial_array)
{
	if (records != initial_array) {  /* A record buffer had been dynamically allocated */
		free(records);
	}
}


#define ALLOC_STRING(dest, source)                      \
    do {                                                \
    const size_t str_size = __builtin_strlen(source) + 1;   \
    __builtin_memcpy(*string_table, source, str_size); \
    dest = *string_table;                               \
    *string_table += str_size;      \
    } while(0);                                              

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
        struct trace_log_descriptor *orig_log_desc = &__static_log_information_start + i;
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

static void copy_log_section_shared_area(int shm_fd, const char *buffer_name,
                                         unsigned int log_descriptor_count,
                                         unsigned int log_param_count,
                                         unsigned int type_definition_count,
                                         unsigned int enum_value_count,
                                         unsigned int alloc_size)
{
    void *mapped_addr = mmap(NULL, alloc_size, PROT_WRITE, MAP_SHARED, shm_fd, 0);
    TRACE_ASSERT((MAP_FAILED != mapped_addr) && (NULL != mapped_addr));
    struct trace_metadata_region *metadata_region = (struct trace_metadata_region *) mapped_addr;
    struct trace_log_descriptor *log_desc = (struct trace_log_descriptor *) metadata_region->data;
    struct trace_type_definition *type_definition = (struct trace_type_definition *)((char *) log_desc + (sizeof(struct trace_log_descriptor) * log_descriptor_count));
    struct trace_param_descriptor *params = (struct trace_param_descriptor *)((char *) type_definition + (type_definition_count * sizeof(struct trace_type_definition)));
    struct trace_enum_value *enum_values = (struct trace_enum_value *) ((char *) params + (log_param_count * sizeof(struct trace_param_descriptor)));
    char *string_table = (char *) enum_values + (enum_value_count * sizeof(struct trace_enum_value));

    strncpy(metadata_region->name, buffer_name, sizeof(metadata_region->name));
    metadata_region->base_address = mapped_addr;
    metadata_region->log_descriptor_count = log_descriptor_count;
    metadata_region->type_definition_count = type_definition_count;
    copy_metadata_to_allocated_buffer(log_descriptor_count, log_desc, params,
                                      type_definition, enum_values,
                                      &string_table);
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
        const struct trace_log_descriptor *element = &__static_log_information_start + i;
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

static void map_static_log_data(const char *buffer_name)
{
    char shm_name[0x100];
    unsigned long log_descriptor_count = &__static_log_information_end - &__static_log_information_start;
    unsigned int alloc_size;
    unsigned int total_log_descriptor_params;
    unsigned int type_definition_count;
    unsigned int enum_value_count;
    static_log_alloc_size(log_descriptor_count, &total_log_descriptor_params, &type_definition_count, &enum_value_count, &alloc_size);
    snprintf(shm_name, sizeof(shm_name), TRACE_STATIC_DATA_REGION_NAME_FMT, getpid());

    int shm_fd = shm_open(shm_name, O_CREAT | O_RDWR, 0660);
    if (shm_fd < 0) {
        return;
    }
    
    TRACE_ASSERT(shm_fd >= 0);
    alloc_size = (alloc_size + 63) & ~63;
    int rc = ftruncate(shm_fd, sizeof(struct trace_metadata_region) + alloc_size);
    TRACE_ASSERT(0 == rc);
    copy_log_section_shared_area(shm_fd, buffer_name, log_descriptor_count, total_log_descriptor_params,
                                 type_definition_count, enum_value_count,
                                 sizeof(struct trace_metadata_region) + alloc_size);

    if (0 != rc) {
        delete_shm_files(getpid());
    }
}

static unsigned get_nearest_power_of_2(unsigned long n)
{
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

static void map_dynamic_log_buffers()
{
    char shm_name[0x100];
    snprintf(shm_name, sizeof(shm_name), TRACE_DYNAMIC_DATA_REGION_NAME_FMT, getpid());
    int shm_fd = shm_open(shm_name, O_CREAT | O_RDWR, 0660);
    if (shm_fd < 0) {
        return;
    }
    TRACE_ASSERT(shm_fd >= 0);
    const size_t buf_size = sizeof(struct trace_buffer)
    		- TRACE_RECORD_BUFFER_RECS  	 * sizeof(struct trace_record)
    		+ TRACE_RECORD_BUFFER_FUNCS_RECS * sizeof(struct trace_record);
    int rc = ftruncate(shm_fd, buf_size);
    TRACE_ASSERT (0 == rc);
    void *mapped_addr = mmap(NULL, buf_size, PROT_WRITE, MAP_SHARED, shm_fd, 0);
    TRACE_ASSERT((MAP_FAILED != mapped_addr) && (NULL != mapped_addr));
    set_current_trace_buffer_ptr((struct trace_buffer *)mapped_addr);
    init_records_metadata();
}

int TRACE__register_buffer(const char *buffer_name)
{
    if (NULL != current_trace_buffer) {
        return -1;
    }

    map_static_log_data(buffer_name);
    map_dynamic_log_buffers();

    return 0;
}

static void get_exec_name(char *exec_name, unsigned int exec_name_size)
{
    char exec_path[512];
    int rc = readlink("/proc/self/exe", exec_path, sizeof(exec_path) - 1);
    if (rc < 0) {
        TRACE_ASSERT(0);
    }

    exec_path[rc] = '\0';

    strncpy(exec_name, basename(exec_path), exec_name_size);    
}

/* Place TRACE__init in the constructors section, which causes it to be executed before main() */
static void TRACE__init(void) __attribute__((constructor));

static void TRACE__init(void)
{
    char buffer_name[512];
    get_exec_name(buffer_name, sizeof(buffer_name));
    TRACE__register_buffer(buffer_name);
}

void TRACE__fini(void)
{
    current_trace_buffer = NULL;
    trace_runtime_control_free_thresholds();
    delete_shm_files(getpid());
}
