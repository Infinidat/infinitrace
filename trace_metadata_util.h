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

#ifndef __TRACE_METADATA_UTIL_H__
#define __TRACE_METADATA_UTIL_H__

#include "trace_defs.h"

/* Fix the base address of metadata to accomodate different shared-mem mappings in different processes */
void relocate_metadata_for_fmt_version(
		const void *original_base_address,
		const void *new_base_address,
		char *data,
		unsigned int descriptor_count,
		unsigned int type_count,
		unsigned int fmt_version);

/* An alternate version that assumes the current format version */
void relocate_metadata(const void *original_base_address, const void *new_base_address, char *data, unsigned int descriptor_count, unsigned int type_count);

size_t get_log_descriptor_size(unsigned fmt_version);

/* Functions for handling the shared-memory areas */
int delete_shm_files(pid_t pid);

#endif 
