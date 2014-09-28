/*
 * trace_shm_util.c
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libgen.h>
#include <assert.h>
#include <errno.h>
#include <alloca.h>

#include "array_length.h"
#include "file_naming.h"
#include "trace_proc_util.h"
#include "trace_lib_internal.h"
#include "trace_shm_util.h"

int trace_shm_delete_files(pid_t pid)
{
    int rc = 0;
    trace_shm_name_buf trace_shm_name;
    struct trace_shm_module_details details = {
            .pid = pid,
    };

    for (trace_module_id_t i = 0; i < TRACE_MODULE_ID_COUNT; i++) {
        details.module_id = i,
        TRACE_ASSERT(trace_generate_shm_name(trace_shm_name, &details, TRACE_SHM_TYPE_STATIC_PER_PROCESS, FALSE) > 0);
        rc |= trace_delete_shm_if_necessary(trace_shm_name);
    }

    TRACE_ASSERT(trace_generate_shm_name(trace_shm_name, &details, TRACE_SHM_TYPE_DYNAMIC, FALSE) > 0);
    rc |= trace_delete_shm_if_necessary(trace_shm_name);
    return rc;
}

int trace_delete_shm_if_necessary(const char *shm_name) {
    const int saved_errno = errno;
    if ((shm_unlink(shm_name) < 0) && (ENOENT != errno)) {
        return -1;
    }

    errno = saved_errno;
    return 0;
}


static int perform_2_path_operation_in_shm_dir(
        int (*func)(const char *p1, const char *p2),
        const char *file1,
        const char *file2)
{
    const size_t len_dir = strlen(trace_shm_get_path());

#define init_path(n) \
    const size_t len##n = strlen(file##n); \
    char *const path##n = alloca(len_dir + len##n + 10); \
    sprintf(path##n, "%s/%s", trace_shm_get_path(), file##n);

    init_path(1);
    init_path(2);

#undef init_path

    return func(path1, path2);
}

int trace_shm_rename(const char *old_name, const char *new_name) {
    if (trace_delete_shm_if_necessary(new_name) < 0) {
        return -1;
    }

    return perform_2_path_operation_in_shm_dir(rename, old_name, new_name);
}

int trace_shm_duplicate(const char *orig_name, const char *duplicate_name)
{
    if (trace_delete_shm_if_necessary(duplicate_name) < 0) {
        return -1;
    }

    return perform_2_path_operation_in_shm_dir(link, orig_name, duplicate_name);
}

int trace_open_shm(const char *shm_name)
{
    return shm_open(shm_name, O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
}

static char shm_dir_path[0x100] = "";

const char *trace_shm_get_path(void)
{
#ifdef SHM_DIR
    if (!shm_dir_path[0]) {
        return SHM_DIR;
    }
#endif
    return shm_dir_path;
}

int trace_shm_init_dir_from_fd(int shm_fd)
{
    char shm_path[PATH_MAX] = "";
    if (trace_get_fd_path(shm_fd, shm_path, sizeof(shm_path)) < 0) {
        return -1;
    }

    shm_dir_path[sizeof(shm_dir_path) - 1] = '\0';
    strncpy(shm_dir_path, dirname(shm_path), sizeof(shm_dir_path));
    if ('\0' != shm_dir_path[sizeof(shm_dir_path) - 1]) {
        shm_dir_path[sizeof(shm_dir_path) - 1] = '\0';
        errno = ENAMETOOLONG;
        return -1;
    }

    return 0;
}

void *trace_shm_set_size_and_mmap(size_t length, int shm_fd)
{
    if (ftruncate(shm_fd, length) < 0) {
        return MAP_FAILED;
    }

    return mmap(NULL, length, PROT_WRITE, MAP_SHARED, shm_fd, 0);
}
