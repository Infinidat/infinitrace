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

#ifndef __TRACE_MACROS_H__
#define __TRACE_MACROS_H__


/* A custom ASSERT macro. If Infinidat's custom assert is present use it.
 * Otherwise if TRACE_HALT_ON_ASSERT is defined hang the offending thread and write to syslog every 5 minutes.
 * If no special behavior is defined, use the standard library's assert macro. */
#ifdef XN_ASSERT

#define TRACE_ASSERT(x) XN_ASSERT(x)

#elif defined(TRACE_HALT_ON_ASSERT)

#include "halt.h"
#define TRACE_ASSERT(x) {if (__builtin_expect((!(x)),0)) { HALT();}}

#else

#ifdef __TRACE_INSTRUMENTATION

#include "trace_fatal.h"
#define TRACE_LOG_ASSERTION_FAILURE(x) (trace_log_assertion_failure(__FILE__, __func__, __LINE__, #x))

#else

#define TRACE_LOG_ASSERTION_FAILURE(x) (0)

#endif

#include <assert.h>
#define TRACE_ASSERT(x) assert((x) || TRACE_LOG_ASSERTION_FAILURE(x))

#endif

#define TRACE_COMPILE_TIME_VERIFY_IS_NON_ZERO(e) (e + (sizeof(struct { int: -!(e);  })))
#define TRACE_COMPILE_TIME_VERIFY_IS_ZERO(e)     (e + (sizeof(struct { int: -!!(e); })))

#define TRACE_COMPILE_TIME_ASSERT_IS_NON_ZERO(e) (void) TRACE_COMPILE_TIME_VERIFY_IS_NON_ZERO(e)
#define TRACE_COMPILE_TIME_ASSERT_IS_ZERO(e)     (void) TRACE_COMPILE_TIME_VERIFY_IS_ZERO(e)
#define TRACE_COMPILE_TIME_ASSERT_EQ(e1, e2)    TRACE_COMPILE_TIME_ASSERT_IS_ZERO((e1) != (e2))

#define REPORT_ERROR_RETURN(ret_val) ERR(__func__, "() (in", __FILE__, ":", __LINE__,") returned", (ret_val));
#define REPORT_AND_RETURN(ret_val) if (0 != (ret_val)) { REPORT_ERROR_RETURN(ret_val); } return ret_val;
#endif  /* __TRACE_MACROS_H__ */
