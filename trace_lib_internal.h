/*
 *  trace_mmap_util.h
 *  Internal API between the per-module trace-runtime and the per-process shared object
 *
 *  Created on: Nov 28, 2013
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

#include <sys/types.h>
#include "bool.h"
#include "trace_lib.h"

/* Map the shared-memory cyclic buffers used to store traces */
int trace_dynamic_log_buffers_map(trace_module_id_t initial_module_ids);

int trace_dynamic_log_buffers_unmap_if_necessary(void);

void trace_runtime_control_free_thresholds(void);

const struct trace_log_descriptor *trace_get_descriptor_ptr(trace_log_id_t log_id)  TRACE_PER_MODULE_SYMBOL;

/* Identifiers that are created by the linker script (see ldwrap.py) and mark the beginning and end of data-structure arrays inserted
 * by the instrumentation mechanism */
extern struct trace_log_descriptor __static_log_information_start[] TRACE_PER_MODULE_SYMBOL;
extern struct trace_log_descriptor __static_log_information_end[]   TRACE_PER_MODULE_SYMBOL;
extern struct trace_type_definition *__type_information_start       TRACE_PER_MODULE_SYMBOL;

trace_module_id_t trace_module_id_alloc(void);

struct trace_static_information {
    struct trace_log_descriptor *log_information_start;
    size_t log_descriptor_count;
    struct trace_type_definition *type_information_start;
    trace_module_id_t module_id;
    const char *module_full_path;
};

enum trace_per_process_limits {
    TRACE_MODULE_ID_COUNT   = (1U << TRACE_RECORD_MODULE_ID_N_BITS),
    TRACE_MODULE_ID_INVALID = -1U,
    TRACE_MODULE_ID_MAX     = TRACE_MODULE_ID_COUNT - 1,
};

void trace_static_log_data_map(const struct trace_static_information *static_info);

/* Obtain the name of the corresponding module given the address of either __static_log_information_start or __static_log_information_end*/
const char *trace_get_module_name(const struct trace_log_descriptor *static_log_information_addr);

/* Check if the current process is not the one that should own the dynamic buffer area, and if so unmap it and reset the module counter */
int trace_buffers_reset_if_new_process(void);

bool_t trace_has_processed_forked_since_init(void);
