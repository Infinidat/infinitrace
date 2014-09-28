/*
 * file_naming.h
 *
 * Establish file naming conventions and declare routines for generating and validating trace file names.
 *
 *  Created on: Dec 3, 2012
 *  Copyright by infinidat (http://infinidat.com)
 *  Author:		Yitzik Casapu, Infinidat
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

#ifndef _TRACE_FILE_NAMING_H_
#define _TRACE_FILE_NAMING_H_

/* Naming conventions for trace output files */
#include <sys/types.h>
#include "bool.h"
#include "trace_lib.h"

#define TRACE_FILE_PREFIX "trace."
#define TRACE_FILE_SUFFIX ".dump"

bool_t trace_is_valid_file_name(const char *name);
int trace_generate_file_name(char *filename, const char *filename_base, size_t name_len, bool_t human_readable);

/* Naming conventions for trace shared-memory buffers */

#define TRACE_SHM_ID "_trace_shm_"
#define TRACE_DYNAMIC_SUFFIX "_dynamic_trace_data"
#define TRACE_STATIC_SUFFIX  "_static_trace_metadata"
/* Format strings with a %d placeholder for the pid */
#define TRACE_DYNAMIC_DATA_REGION_NAME_FMT TRACE_SHM_ID "%d" TRACE_DYNAMIC_SUFFIX
#define TRACE_STATIC_PER_PROCESS_DATA_REGION_NAME_FMT  TRACE_SHM_ID "%d_%u" TRACE_STATIC_SUFFIX

enum trace_shm_object_type {
    TRACE_SHM_TYPE_ANY = 0,             /* can't be used to generate a file name, only for inquiries */
    TRACE_SHM_TYPE_DYNAMIC,
    TRACE_SHM_TYPE_STATIC_PER_PROCESS,
    TRACE_SHM_TYPE_STATIC_PER_FILE,     /* Will be used in the future to keep a single copy of metadata from a shared-object used by multiple processes */
    TRACE_SHM_TYPE_COUNT                /* Must come last */
};

struct trace_shm_module_details {
    pid_t pid;
    trace_module_id_t module_id;
    const char *file_name;
    const char *file_dir;
};

typedef char trace_shm_name_buf[sizeof(TRACE_STATIC_PER_PROCESS_DATA_REGION_NAME_FMT) + 0x40];
int trace_generate_shm_name(trace_shm_name_buf buf, const struct trace_shm_module_details *details, enum trace_shm_object_type shm_type, bool_t temporary);
pid_t trace_get_pid_from_shm_name(const char *shm_name);

#endif /* _TRACE_FILE_NAMING_H_ */
