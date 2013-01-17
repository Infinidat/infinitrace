/*
 * trace_str_util.c
 *
 *  Created on: Oct 16, 2012
 *      Author: yitzikc
 */


/*
 * trace_str_util.c
 * Created on: Oct 16, 2012 by Yitzik Casapu of Infinidat
 *
 ***
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

#include <string.h>
#include <stdlib.h>
#include "trace_str_util.h"


#define TRACE_SEV_X(v, str) [v] = #str,
const char *const trace_severity_to_str_array[] = {
	[0] = "INVALID",
	[1] = "FUNCTION_TRACE",
	TRACE_SEVERITY_DEF
	[TRACE_SEV__COUNT] = NULL
};
#undef TRACE_SEV_X

#define TRACE_SEV_X(unused, name)                   \
     if (COMP_FUNC(s, #name) == 0) { \
         return TRACE_SEV_##name;                   \
     }

static enum trace_severity num_to_severity(const char *s)
{
    long long num = -1;
    bool_t is_num = trace_get_number(s, &num);

    if (is_num && (num >= TRACE_SEV_INVALID) && (num <= TRACE_SEV__MAX)) {
        return (enum trace_severity) num;
    }

    return TRACE_SEV_INVALID;
}

enum trace_severity trace_str_to_severity_case_sensitive(const char *s)
{
    const size_t len_s = strlen(s);

    /* We are not using strcmp() here because on Linux it is a macro, whose expansion makes Coverity complain about dead code */
#define COMP_FUNC(s, ref)  !( (sizeof(ref) - 1 == len_s) && (memcmp(s, ref, sizeof(ref) - 1) == 0) )

	TRACE_SEVERITY_DEF

#undef COMP_FUNC

	return num_to_severity(s);
}

enum trace_severity trace_str_to_severity_case_insensitive(const char *s)
{
#define COMP_FUNC strcasecmp

	TRACE_SEVERITY_DEF

#undef COMP_FUNC

	return num_to_severity(s);
}

#undef TRACE_SEV_X


bool_t trace_get_number(const char* str, long long *num) { /* home made atoll / strtoll */
    if (! (str && *str)) return FALSE;
    int negative = 0;
    long long n = 0;
    if (str[0] == '-' || str[0] == '+') {
        negative = str[0] == '-';
        str++;
    }
    if (str[0] == '0' && (str[1] | 0x20) == 'x') {
        str += 2;
        while (*str) {
            if ((*str < '0' || *str > '9') && ((*str|0x20) < 'a' || (*str|0x20) > 'f'))
                return 0;
            n *= 0x10;
            n += (*str > '9') ? ((*str|0x20) - ('a' - 10)) : *str-'0';
            str++;
        }
    }
    else {
        while  (*str) {
            if (*str < '0' || *str > '9')
                return FALSE;
            n *= 10;
            n += *str - '0';
            str++;
        }
    }
    *num = negative ? 0-n : n;
    return TRUE;
}

size_t trace_strncpy(char* dest, const char* source, size_t max_size)
{
	const char* p = memccpy(dest, source, '\0', max_size);
	if (p == NULL) {
		return max_size;
	} else {
		return p - dest - 1;
	}
}
