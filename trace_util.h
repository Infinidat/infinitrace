/*
 * trace_util.h
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

#ifndef __TRACE_UTIL_H__
#define __TRACE_UTIL_H__

#include "trace_defs.h"

#ifdef __cplusplus
 extern "C" {
#endif


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


#endif /* __TRACE_UTIL_H__ */
