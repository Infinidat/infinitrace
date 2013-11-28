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
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <limits.h>

#include "trace_macros.h"
#include "trace_lib_internal.h"
#include "trace_shm_util.h"
#include "trace_proc_util.h"
#include "file_naming.h"
#include "halt.h"

void trace_init_static_information(struct trace_static_information *static_info)
{
    static_info->log_information_start  = __static_log_information_start;
    static_info->log_descriptor_count   = __static_log_information_end - __static_log_information_start;
    static_info->type_information_start = __type_information_start;
    static_info->module_id              = trace_module_id_alloc();
}

static int TRACE__register_buffer(const char *buffer_name)
{
    int rc = 0;
    struct trace_static_information static_info;
    trace_init_static_information(&static_info);
    trace_static_log_data_map(&static_info, buffer_name);
    if ((0 == static_info.module_id) && !trace_is_initialized()) {
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
int TRACE__implicit_init(void) __attribute__((constructor, visibility ("hidden")));

int TRACE__implicit_init(void) {
    assert(0 == trace_init(NULL));
    return 0;
}

void TRACE__fini(void)
{
    TRACE_ASSERT(0 == trace_finalize());
}

trace_log_id_t trace_get_descriptor_id(const struct trace_log_descriptor *descriptor)
{
    TRACE_ASSERT((descriptor >= __static_log_information_start) && (descriptor < __static_log_information_end));
    return (trace_log_id_t) (descriptor - __static_log_information_start);
}

const struct trace_log_descriptor *trace_get_descriptor_ptr(trace_log_id_t log_id)
{
    return __static_log_information_start + log_id;
}
