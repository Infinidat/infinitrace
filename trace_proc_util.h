/*
 * trace_proc_util.h: Routines for process management and data extraction from the proc filesystem.
 *
 *  Created on: Jul 10, 2013
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

#ifndef TRACE_PROC_UTIL_H_
#define TRACE_PROC_UTIL_H_

#include <errno.h>
#include <sys/types.h>

#include "bool.h"
#include "min_max.h"
#include "trace_clock.h"

/* Get the name of the current executable. Return 0 if successful, -1 otherwise. */
int trace_get_current_exec_basename(char *exec_name, size_t exec_name_size);

/* Obtain the full path of the file corresponding to a the file-descriptor fd. Return 0 if successful, -1 otherwise. */
int trace_get_fd_path(int fd, char *file_path, size_t file_path_buf_size);

/* A wrapper for the fork() system call, which allows a user-supplied function to be called in order to initialize
 * the child process, delays the execution of the parent until the child is initialized and returns a consistent
 * status on both the parent the the child.
 * The following functions are supplied as arguments:
 * - child_init: Called from the child process to initialize the child.
 * - cleanup_on_failure: Used to perform clean-up if the child initialization fails. May be called from either the parent or the child, and takes the child's pid as
 *   an argument.
 * Both functions return a negative value on failure, otherwise a result >= 0. On failure, they must set errno != 0.
 *  */
pid_t trace_fork_with_child_init(
        int (*child_init)(void),
        int (*cleanup_on_failure)(pid_t child_pid)
        );

/* Cap the value of errno at 0xFF so that it can be safely relayed to a parent process via the 8 bits available in the exit status. */
static inline int trace_capped_errno()
{
    return MIN(errno, 0xFF);
}

/* Check whether the process 'pid' exists */
bool_t trace_process_exists(pid_t pid);

/* Get the last execution time of the process 'pid' intp 'curtime'. Return 0 on success, -1 otherwise. */
int trace_get_process_time(pid_t pid, trace_ts_t *curtime);

/* Check whether the process 'pid' is descended from any of the process given as 'potential_parents' */
bool_t trace_is_process_descended_from_pids(pid_t pid, const pid_t potential_parents[], size_t n_potential_parents);

#endif /* TRACE_PROC_UTIL_H_ */
