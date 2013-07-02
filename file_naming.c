/*
 * file_naming.c
 *
 * Routines for generating and validating trace file names.
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <assert.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "file_naming.h"
#include "trace_clock.h"
#include "trace_str_util.h"

bool_t trace_is_valid_file_name(const char *name)
{
	static const char prefix[] = TRACE_FILE_PREFIX;
	static const char suffix[] = TRACE_FILE_SUFFIX;
	const size_t prefix_len = strlen(prefix);

	assert(prefix[prefix_len - 1] == '.');
	assert(suffix[0] == '.');

	if (strncmp(prefix, name, prefix_len) != 0) {
		return FALSE;
	}

	/* We can safely assume strrchr() will not return NULL because there's at least one '.' at the end of the prefix */
	return strcmp(strrchr(name + prefix_len - 1, '.'), suffix) == 0;
}

int trace_generate_file_name(char *filename, const char *filename_base, size_t name_len, bool_t human_readable)
{
	const unsigned long long now_ms = trace_get_walltime_ms();

	if (! human_readable) {
		/* An old format which uses milliseconds since the epoch. Provided as an option for backward compatiblity */
		return snprintf(filename, name_len, "%s/" TRACE_FILE_PREFIX "%llu" TRACE_FILE_SUFFIX, filename_base, now_ms);
	}

	struct tm now_tm;
	const time_t now_sec = now_ms / 1000ULL;
	gmtime_r(&now_sec, &now_tm);
	int len = snprintf(filename, name_len, "%s/" TRACE_FILE_PREFIX, filename_base);
	len += strftime(filename + len, name_len - len, "%F--%H-%M-%S--", &now_tm);
	return len + snprintf(filename + len, name_len - len, "%02llu" TRACE_FILE_SUFFIX, (now_ms % 1000) / 10);
}

int trace_generate_shm_name(trace_shm_name_buf buf, pid_t pid, enum trace_shm_object_type shm_type, bool_t temporary)
{
    const char *fmt = NULL;

    switch (shm_type) {
    case TRACE_SHM_TYPE_DYNAMIC:
        fmt = TRACE_DYNAMIC_DATA_REGION_NAME_FMT "%s";
        break;

    case TRACE_SHM_TYPE_STATIC:
        fmt = TRACE_STATIC_DATA_REGION_NAME_FMT "%s";
        break;

    default:
        errno = EINVAL;
        return -1;
    }

    const int buf_len = sizeof(trace_shm_name_buf);
    const char *const extra_suffix = temporary ? ".tmp" : "";
    const int len = snprintf(buf, buf_len, fmt, (int) pid, extra_suffix);
    if (len >= buf_len) {
        errno = ENAMETOOLONG;
        return -1;
    }

    return len;
}

pid_t trace_get_pid_from_shm_name(const char *shm_name)
{
    if (! trace_str_starts_with_prefix(shm_name, TRACE_SHM_ID)) {
        errno = EINVAL;
        return -1;
    }

    shm_name += strlen(TRACE_SHM_ID);
    const char *const underscore = strchr(shm_name, '_');

    if (NULL == underscore) {
        errno = EINVAL;
        return -1;
    }

    const size_t pid_str_len = underscore - shm_name;
    const char *const pid_str = strndupa(shm_name, pid_str_len);
    return atoi(pid_str);
}
