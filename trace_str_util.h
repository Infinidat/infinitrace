/*
 * trace_str_util.h
 *
 ***
Copyright 2012 Yotam Rubin <yotamrubin@gmail.com>
   Sponsored by infinidat (http://infinidat.com)

   Revised and maintained by Yitzik Casapu of Infinidat

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

/* Trace dumper inline utility functions */

#ifndef __TRACE_STR_UTIL_H__
#define __TRACE_STR_UTIL_H__

#include <sys/types.h>
#include "trace_defs.h"
#include "bool.h"
#include "min_max.h"

#ifdef __cplusplus
 extern "C" {
#endif


 extern const char *const trace_severity_to_str_array[];

 enum trace_severity trace_str_to_severity_case_sensitive(const char *s);
 enum trace_severity trace_str_to_severity_case_insensitive(const char *s);

 /* home made atoll / strtoll.
 *  Handles numbers in both decimal and hexadecimal representation.
 *  Returns TRUE on success, FALSE, otherwise */
 bool_t trace_get_number(const char* str, long long *num);

 /* A custom string copy routine. Copy the content of source to dest, up to max_size bytes, including the terminating null byte if present.
  * Return the number of bytes copied excluding the null byte */
 size_t trace_strncpy(char* dest, const char* source, size_t max_size);

 /* A wrapper for trace_strncpy which guarantees that the destination string will be null terminated. Hence its length cannot exceed max_size - 1 */
 static inline size_t trace_strncpy_and_terminate(char* dest, const char* source, size_t max_size)
 {
	 const size_t n_copied = trace_strncpy(dest, source, max_size - 1);
	 dest[n_copied] = '\0';
	 return n_copied;
 }

 /* A wrapper macro for trace_strncpy, which copies a string between char arrays. The size is computed automatically. */
#define trace_array_strcpy(dest, src) trace_strncpy_and_terminate((char *)(dest), (const char *)(src), MIN(sizeof(dest), sizeof(src)))

 /* Note: the inline functions below are deprecated. Use the standard strcmp or trace_str_to_severity_case_sensitive instead in new code.
  * Presently they are only used by the trace instrumentor code. */
 static inline int trace_strcmp(const char *s1, const char *s2)
 {
      /* Move s1 and s2 to the first differing characters
         in each string, or the ends of the strings if they
         are identical.  */
      while (*s1 != '\0' && *s1 == *s2) {
          s1++;
          s2++;
      }
      /* Compare the characters as unsigned char and
         return the difference.  */
      const unsigned char uc1 = (*(const unsigned char *) s1);
      const unsigned char uc2 = (*(const unsigned char *) s2);
      return ((uc1 < uc2) ? -1 : (uc1 > uc2));
  }

 #define TRACE_SEV_X(num, name)                  \
     if (trace_strcmp(function_name, #name) == 0) { \
         return TRACE_SEV_##name;                \
     }

 static inline enum trace_severity trace_function_name_to_severity(const char *function_name) {
     TRACE_SEVERITY_DEF;
     #undef TRACE_SEV_X
     return TRACE_SEV_INVALID;
 }

#ifdef __cplusplus
}
#endif


#endif /* __TRACE_STR_UTIL_H__ */
