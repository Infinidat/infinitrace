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

#ifndef __MACROS_H__
#define __MACROS_H__


/* A custom ASSERT macro. If Infinidat's custom assert is present use it. Otherwise hang the offending thread and write to syslog every 5 minutes. */
#ifdef XN_ASSERT

#define TRACE_ASSERT(x) XN_ASSERT(x)

#elif defined(TRACE_HALT_ON_ASSERT)

#include "halt.h"
#define TRACE_ASSERT(x) {if (__builtin_expect((!(x)),0)) { HALT();}}

#else

#include <assert.h>
#define TRACE_ASSERT(x) assert(x)

#endif

#define REPORT_ERROR_RETURN(ret_val) ERR(__func__, "() (in", __FILE__, ":", __LINE__,") returned", (ret_val));
#define REPORT_AND_RETURN(ret_val) if (0 != (ret_val)) { REPORT_ERROR_RETURN(ret_val); } return ret_val;
#endif
