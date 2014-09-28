/*
 * trace_shm_util.h
 * Functions for manipulating the shared-memory objects.
 *
 *  Created on: Nov 21, 2013
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

#ifndef TRACE_SHM_UTIL_H_
#define TRACE_SHM_UTIL_H_

int trace_shm_delete_files(pid_t pid);

int trace_delete_shm_if_necessary(const char *shm_name);


int trace_shm_rename(const char *old_name, const char *new_name);

int trace_shm_duplicate(const char *orig_name, const char *duplicate_name);

int trace_open_shm(const char *shm_name);

int trace_shm_init_dir_from_fd(int shm_fd);

const char *trace_shm_get_path(void);

void *trace_shm_set_size_and_mmap(size_t length, int shm_fd);

#endif /* TRACE_SHM_UTIL_H_ */
