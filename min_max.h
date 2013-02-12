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

#ifndef __MIN_MAX_H__
#define __MIN_MAX_H__

#define __TRACE_STDC_MIN(x, y) ((x)<(y) ? (x):(y))
#define __TRACE_STDC_MAX(x, y) ((x)>(y) ? (x):(y))

#ifndef __GNUC__

#warning "Using standard C versions of MIN and MAX, which evaluate their arguments multiple times"

#define MIN(x, y) __TRACE_STDC_MIN(x, y)
#define MAX(x, y) __TRACE_STDC_MAX(x, y)

#else

#ifdef __cplusplus
#define __TRACE_CMP_REF &
#else
#define __TRACE_CMP_REF
#endif

#define MIN(x, y) ({ const __typeof__(x) __TRACE_CMP_REF __tmp_x = x; const __typeof__(y) __TRACE_CMP_REF __tmp_y = y; __TRACE_STDC_MIN(__tmp_x, __tmp_y); })
#define MAX(x, y) ({ const __typeof__(x) __TRACE_CMP_REF __tmp_x = x; const __typeof__(y) __TRACE_CMP_REF __tmp_y = y; __TRACE_STDC_MAX(__tmp_x, __tmp_y); })

#endif /* __GNUC__ */

#endif 
