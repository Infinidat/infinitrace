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

#include "bool.h"

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
#define TRACE_STATIC_DATA_REGION_NAME_FMT  TRACE_SHM_ID "%d" TRACE_STATIC_SUFFIX


#endif /* _TRACE_FILE_NAMING_H_ */
