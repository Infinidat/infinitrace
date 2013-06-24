/*
 *  trace_mmap_util.h
 *  Routines for working with memory mappings
 *
 *  Created on: Oct 20, 2013
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

#ifndef TRACE_MMAP_UTIL_H_
#define TRACE_MMAP_UTIL_H_

#include <sys/mman.h>
#include <sys/types.h>

/* Obtain a buffer of private memory from the OS */
void *trace_mmap_private_anon_mem(size_t size);

/* Grow a memory mapping, using mremap() where available. If addr is NULL then size must also be NULL, and new memory is allocated */
void *trace_mmap_grow(void *const addr, size_t size, size_t new_size);

/* Round the given size to the nearest multiple of 'multiple', which must be a power of 2. */
size_t trace_round_size_up_to_multiple(size_t size, size_t multiple);

/* Get the system page size from the system. After the first call the result is cached */
size_t trace_get_page_size();

/* Round size up to the nearest multiple of the system page size */
size_t trace_round_size_up_to_page_size(size_t size);

/* Unmap memory of size len from the address *mapping_base. If successful set *mapping_base to MAP_FAILED */
int trace_munmap_if_necessary(void **mapping_base, size_t len);

#endif /* TRACE_MMAP_UTIL_H_ */
