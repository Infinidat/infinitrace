/***
 * trace_user_per_module.c
 * Trace Runtime support routines and data structures that should have a separate instance in each traced module (either a shared-object or an executable)
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
***/

#include "platform.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "trace_macros.h"
#include "trace_lib.h"
#include "trace_user.h"
#include "min_max.h"
#include "trace_metadata_util.h"
#include "trace_shm_util.h"
#include "trace_clock.h"
#include "trace_proc_util.h"
#include "bool.h"
#include "file_naming.h"
#include "halt.h"

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

static void copy_log_section_shared_area(int shm_fd, const char *buffer_name,
                                         unsigned int log_descriptor_count,
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

static void map_static_log_data(const char *buffer_name)
{
    trace_shm_name_buf shm_name;
    unsigned long log_descriptor_count = __static_log_information_end - __static_log_information_start;
    unsigned int alloc_size;
    unsigned int total_log_descriptor_params;
    unsigned int type_definition_count;
    unsigned int enum_value_count;

    TRACE_ASSERT(trace_generate_shm_name(shm_name, getpid(), TRACE_SHM_TYPE_STATIC, FALSE) > 0);
    const int shm_fd = trace_open_shm(shm_name);
    TRACE_ASSERT(shm_fd >= 0);
    
    static_log_alloc_size(log_descriptor_count, &total_log_descriptor_params, &type_definition_count, &enum_value_count, &alloc_size);
    alloc_size = (alloc_size + TRACE_RECORD_SIZE - 1) & ~(TRACE_RECORD_SIZE - 1);
    copy_log_section_shared_area(shm_fd, buffer_name, log_descriptor_count, total_log_descriptor_params,
                                 type_definition_count, enum_value_count,
                                 sizeof(struct trace_metadata_region) + alloc_size);
    TRACE_ASSERT(0 == close(shm_fd));
}

int TRACE__register_buffer(const char *buffer_name)
{
    int rc = 0;
    map_static_log_data(buffer_name);
    if (! trace_is_initialized()) {
        rc = trace_dynamic_log_buffers_map();
        if (rc < 0) {
            trace_shm_name_buf shm_name;
            TRACE_ASSERT(trace_generate_shm_name(shm_name, getpid(), TRACE_SHM_TYPE_STATIC, FALSE) > 0);
            trace_delete_shm_if_necessary(shm_name);
        }
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
int TRACE__implicit_init(void) __attribute__((constructor));

int TRACE__implicit_init(void) {
    assert(0 == trace_init(NULL));
    return 0;
}

void TRACE__fini(void)
{
    TRACE_ASSERT(0 == trace_finalize());
}
