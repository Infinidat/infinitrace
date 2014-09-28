/*
 * trace_user_shm_setup.c
 *
 *  Created on: Nov 28, 2013
 * Trace Runtime support routines and data structures that should have a single instance in each traced process
 *
 *  Created on: Nov 20, 2013
 *  Original Author: Yotam Rubin, 2012
 *  Maintainer:      Yitzik Casapu, Infinidat
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


#include "platform.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <libgen.h>
#include <dlfcn.h>


#include "trace_macros.h"
#include "trace_lib_internal.h"
#include "trace_user.h"
#include "trace_metadata_util.h"
#include "trace_shm_util.h"
#include "trace_str_util.h"
#include "file_naming.h"
#include "halt.h"

#pragma GCC diagnostic ignored "-Wvla"  /* Allow C99 variable-length arrays */

static pid_t saved_pid = -1;

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
    recs->mutab.last_committed_record = TRACE_RECORD_INVALID_COUNT;
    memset(recs->records, TRACE_SEV_INVALID, sizeof(recs->records[0]));
    TRACE_ASSERT(recs->imutab.max_records > 0);
    memset(recs->records + recs->imutab.max_records - 1, TRACE_SEV_INVALID, sizeof(recs->records[0]));
}

static void init_sev_to_buffer_cache(void)
{
    int i, j;
    for (i = 0; i < TRACE_SEV__COUNT; i++) {
        current_trace_buffer->buffer_indices[i] = &(current_trace_buffer->u.records._funcs) - current_trace_buffer->u._all_records; /* Default */
        for (j = 0; j < current_trace_buffer->n_record_buffers; j++) {
            if ((1U << i) & current_trace_buffer->u._all_records[j].imutab.severity_type) {
                current_trace_buffer->buffer_indices[i] = j;
                break;
            }
        }
    }
}

static void init_records_metadata(void)
{

    current_trace_buffer->n_record_buffers = TRACE_BUFFER_NUM_RECORDS;
    current_trace_buffer->pid = getpid();
    saved_pid = current_trace_buffer->pid;

#define ALL_SEVS_ABOVE(sev) (((1 << (TRACE_SEV__MAX + 1))) - (1 << (sev + 1)))

    init_records_immutable_data(&current_trace_buffer->u.records._above_info, TRACE_RECORD_BUFFER_RECS, ALL_SEVS_ABOVE(TRACE_SEV_INFO));
    init_records_immutable_data(&current_trace_buffer->u.records._other, TRACE_RECORD_BUFFER_RECS, ALL_SEVS_ABOVE(TRACE_SEV_DEBUG) & ~ALL_SEVS_ABOVE(TRACE_SEV_INFO));
    init_records_immutable_data(&current_trace_buffer->u.records._debug, TRACE_RECORD_BUFFER_RECS, (1 << TRACE_SEV_DEBUG));
    init_records_immutable_data(&current_trace_buffer->u.records._funcs, TRACE_RECORD_BUFFER_FUNCS_RECS, (1 << TRACE_SEV_FUNC_TRACE));

#undef ALL_SEVS_ABOVE

    init_sev_to_buffer_cache();

    init_record_mutable_data(&(current_trace_buffer->u.records._above_info));
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

static void set_current_trace_buffer_ptr(struct trace_buffer *trace_buffer_ptr)
{
    current_trace_buffer = trace_buffer_ptr;
}

int trace_dynamic_log_buffers_map(trace_module_id_t initial_module_ids)
{
    trace_shm_name_buf shm_tmp_name;
    const struct trace_shm_module_details details = {
            .pid = getpid()
    };
    TRACE_ASSERT(trace_generate_shm_name(shm_tmp_name, &details, TRACE_SHM_TYPE_DYNAMIC, TRUE) > 0);

    const int shm_fd = trace_open_shm(shm_tmp_name);
    if (shm_fd < 0) {
        return shm_fd;
    }

    if (trace_shm_init_dir_from_fd(shm_fd) < 0) {
        close(shm_fd);
        return -1;
    }

    const size_t buf_size = calc_dymanic_buf_size();
    void *const mapped_addr = trace_shm_set_size_and_mmap(buf_size, shm_fd);

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
    current_trace_buffer->module_ids_allocated  = initial_module_ids;
    current_trace_buffer->module_ids_discovered = 0;

    /* In order to avoid a possible race condition of the dumper accessing the shared-memory area before it is fully initialized, we only rename it
     * to the name the dumper expects after completing its initialization. */
    trace_shm_name_buf shm_name;
    TRACE_ASSERT(trace_generate_shm_name(shm_name, &details, TRACE_SHM_TYPE_DYNAMIC, FALSE) > 0);
    if (trace_shm_rename(shm_tmp_name, shm_name) < 0) {
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

int trace_dynamic_log_buffers_unmap_if_necessary()
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
        saved_pid = -1;
    }

    TRACE_ASSERT(NULL == current_trace_buffer);
    return 0;
}

bool_t trace_has_processed_forked_since_init(void)
{
    return (saved_pid >= 0) && (getpid() != saved_pid);
}

/* Routines for initializing static information buffers that contain per-module metadata describing the module's traces */

/* Functions for creating the per traced process shared-memory areas at runtime. */

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


static void copy_log_descriptors_to_allocated_buffer(const struct trace_static_information *static_info, struct trace_log_descriptor *log_desc, struct trace_param_descriptor *params,
                                                     char **string_table)

{
#if TRACE_FORMAT_VERSION >= TRACE_FORMAT_VERSION_INTRODUCED_FILE_FUNCTION_METADATA
    const char *last_file = NULL;
    const char *last_function = NULL;
#endif

    /* NOTE: The allocations performed in this function should not exceed the size computed in static_log_alloc_size. Care should be taken to keep the algorithms
     * use here and there compatible. */

    unsigned int i;
    for (i = 0; i < static_info->log_descriptor_count; i++) {
        struct trace_log_descriptor *orig_log_desc = static_info->log_information_start + i;
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

static void copy_type_definitions_to_allocated_buffer(const struct trace_static_information *static_info, struct trace_type_definition *type_definition,
                                                      struct trace_enum_value *enum_values, char **string_table)
{
    const struct trace_type_definition *type = static_info->type_information_start;
    while (type && type->type_name) {
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
            TRACE_ASSERT(0);
            break;
        }

        type_definition++;
        type = *((struct trace_type_definition **) ((char *) type + sizeof(*type)));
    }
}

static void copy_metadata_to_allocated_buffer(const struct trace_static_information *static_info, struct trace_log_descriptor *log_desc, struct trace_param_descriptor *params,
                                              struct trace_type_definition *type_definition, struct trace_enum_value *enum_values,
                                              char **string_table)
{
    copy_log_descriptors_to_allocated_buffer(static_info, log_desc, params, string_table);
    copy_type_definitions_to_allocated_buffer(static_info, type_definition, enum_values, string_table);
}

static void copy_log_section_shared_area(int shm_fd,
                                         const struct trace_static_information *static_info,
                                         unsigned int log_param_count,
                                         unsigned int type_definition_count,
                                         unsigned int enum_value_count,
                                         unsigned int alloc_size)
{
    void *const mapped_addr = trace_shm_set_size_and_mmap(alloc_size, shm_fd);
    TRACE_ASSERT((MAP_FAILED != mapped_addr) && (NULL != mapped_addr));
    struct trace_metadata_region *metadata_region = (struct trace_metadata_region *) mapped_addr;
    TRACE_ASSERT((NULL == metadata_region->base_address) && ('\0' == metadata_region->name[0]));

    struct trace_log_descriptor *log_desc = (struct trace_log_descriptor *) metadata_region->data;
    struct trace_type_definition *type_definition = (struct trace_type_definition *)((char *) log_desc + (sizeof(struct trace_log_descriptor) * static_info->log_descriptor_count));
    struct trace_param_descriptor *params = (struct trace_param_descriptor *)((char *) type_definition + (type_definition_count * sizeof(struct trace_type_definition)));
    struct trace_enum_value *enum_values = (struct trace_enum_value *) ((char *) params + (log_param_count * sizeof(struct trace_param_descriptor)));
    char *string_table = (char *) enum_values + (enum_value_count * sizeof(struct trace_enum_value));

    metadata_region->log_descriptor_count = static_info->log_descriptor_count;
    metadata_region->type_definition_count = type_definition_count;
    copy_metadata_to_allocated_buffer(static_info, log_desc, params,
                                      type_definition, enum_values,
                                      &string_table);

    char mod_path[strlen(static_info->module_full_path) + 1];
    memcpy(mod_path, static_info->module_full_path, sizeof(mod_path));
    trace_strncpy_and_terminate(metadata_region->name, basename(mod_path), sizeof(metadata_region->name));

#if (TRACE_FORMAT_VERSION >= TRACE_FORMAT_VERSION_INTRODUCED_MODULE_FULL_PATH)
    memcpy(mod_path, static_info->module_full_path, sizeof(mod_path));
    trace_strncpy_and_terminate(metadata_region->mod_dir, dirname(mod_path), sizeof(metadata_region->mod_dir));
#endif

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
        TRACE_ASSERT(0);
        break;
    }
}

static void type_alloc_size(struct trace_type_definition *type_start, unsigned int *type_definition_count, unsigned int *enum_value_count,
                            unsigned int *alloc_size)
{
    *type_definition_count = 0;
    *enum_value_count = 0;

    struct trace_type_definition *type = (struct trace_type_definition *) type_start;
    while (type && type->type_name) {
        (*type_definition_count)++;
        type_definition_alloc_size(type, enum_value_count, alloc_size);
        type = *((struct trace_type_definition **) ((char *) type + sizeof(*type_start)));
    }
}

static void static_log_alloc_size(const struct trace_static_information *static_info,
                                  unsigned int *total_params,
                                  unsigned int *type_definition_count,
                                  unsigned int *enum_value_count,
                                  unsigned int *alloc_size)
{
    unsigned int i;
    *alloc_size = 0;
    *total_params = 0;

    const char *latest_file = NULL;
    const char *latest_function = NULL;

    for (i = 0; i < static_info->log_descriptor_count; i++) {
        const struct trace_log_descriptor *element = static_info->log_information_start + i;
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

    type_alloc_size(static_info->type_information_start, type_definition_count, enum_value_count, alloc_size);
}

void trace_static_log_data_map(const struct trace_static_information *static_info)
{
    trace_shm_name_buf shm_name;
    unsigned int alloc_size;
    unsigned int total_log_descriptor_params;
    unsigned int type_definition_count;
    unsigned int enum_value_count;

    const struct trace_shm_module_details details = {
            .pid = getpid(),
            .module_id = static_info->module_id,
    };
    TRACE_ASSERT(trace_generate_shm_name(shm_name, &details, TRACE_SHM_TYPE_STATIC_PER_PROCESS, FALSE) > 0);
    const int shm_fd = trace_open_shm(shm_name);
    TRACE_ASSERT(shm_fd >= 0);

    static_log_alloc_size(static_info, &total_log_descriptor_params, &type_definition_count, &enum_value_count, &alloc_size);
    alloc_size = (alloc_size + TRACE_RECORD_SIZE - 1) & ~(TRACE_RECORD_SIZE - 1);
    copy_log_section_shared_area(shm_fd, static_info, total_log_descriptor_params,
                                 type_definition_count, enum_value_count,
                                 sizeof(struct trace_metadata_region) + alloc_size);
    TRACE_ASSERT(0 == close(shm_fd));
}

const char *trace_get_module_name(const struct trace_log_descriptor *static_log_information_addr)
{
    Dl_info info;
    memset(&info, 0, sizeof(info));
    if (0 == dladdr(static_log_information_addr, &info)) {  /* Here 0 represents failure */
        return NULL;
    }

    return info.dli_fname;
}
