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
#include <regex.h>

#include "trace_clock.h"
#include "trace_str_util.h"
#include "array_length.h"
#include "trace_macros.h"
#include "file_naming.h"


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

int trace_generate_shm_name(trace_shm_name_buf buf, const struct trace_shm_module_details *details, enum trace_shm_object_type shm_type, bool_t temporary)
{
    const char *const extra_suffix = temporary ? ".tmp" : "";
    const int buf_len = sizeof(trace_shm_name_buf) - strlen(extra_suffix);
    int len = 0;
    switch (shm_type) {
    case TRACE_SHM_TYPE_DYNAMIC:
        len = snprintf(buf, buf_len, TRACE_DYNAMIC_DATA_REGION_NAME_FMT, (int) (details->pid));
        break;

    case TRACE_SHM_TYPE_STATIC_PER_PROCESS:
        len = snprintf(buf, buf_len, TRACE_STATIC_PER_PROCESS_DATA_REGION_NAME_FMT,
                (int) (details->pid), (unsigned) (details->module_id));
        break;

    case TRACE_SHM_TYPE_STATIC_PER_FILE:
    case TRACE_SHM_TYPE_ANY:
    case TRACE_SHM_TYPE_COUNT:
    default:
        errno = EINVAL;
        return -1;
    }

    if (len >= buf_len) {
        buf[buf_len - 1] = '\0';
        errno = ENAMETOOLONG;
        return -1;
    }

    return stpcpy(buf + len, extra_suffix) - buf;
}

#define SHM_GENERIC_PREFIX_REGEXP TRACE_SHM_ID "([[:digit:]]{1,6})"

static const char shm_generic_regexp[] = SHM_GENERIC_PREFIX_REGEXP "_.+ic_trace_.*data";
static const char shm_dynamic_regexp[] = SHM_GENERIC_PREFIX_REGEXP TRACE_DYNAMIC_SUFFIX;
static const char shm_static_regexp[]  = SHM_GENERIC_PREFIX_REGEXP "_([[:digit:]]+)" TRACE_STATIC_SUFFIX;

#undef SHM_GENERIC_PREFIX_REGEXP

static regex_t file_type_regexps[TRACE_SHM_TYPE_COUNT];

static void compile_regexps(void) __attribute__((constructor));
static void compile_regexps(void)
{
    memset(file_type_regexps, 0, sizeof(file_type_regexps));
    TRACE_ASSERT(0 == regcomp(file_type_regexps + TRACE_SHM_TYPE_DYNAMIC, shm_dynamic_regexp, REG_EXTENDED));
    TRACE_ASSERT(0 == regcomp(file_type_regexps + TRACE_SHM_TYPE_STATIC_PER_PROCESS, shm_static_regexp, REG_EXTENDED));
    TRACE_ASSERT(0 == regcomp(file_type_regexps + TRACE_SHM_TYPE_ANY, shm_generic_regexp, REG_EXTENDED));
}

static long long get_number_from_match_group(const char *s, const regmatch_t *match)
{
    long long result = -1;
    /* We assert that we get an invalid number, since the regexp should have checked for that */
    TRACE_ASSERT(trace_get_number_from_substring(s + match->rm_so, match->rm_eo - match->rm_so, &result));
    return result;
}

pid_t trace_get_pid_from_shm_name(const char *shm_name)
{
    regmatch_t matches[2];
    if (0 != regexec(file_type_regexps + TRACE_SHM_TYPE_ANY, shm_name, ARRAY_LENGTH(matches), matches, 0)) {
        errno = EINVAL;
        return -1;
    }

    return (pid_t) get_number_from_match_group(shm_name, matches + 1);
}
