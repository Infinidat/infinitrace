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
/* Allows code with tracing to compile without linking tracing */


#include "trace_lib.h"
#include "trace_user.h"

void TRACE_REPR_CALL_NAME ()
{
}

#define TRACE_SEV_X(ignored, sev) void sev() {}

TRACE_SEVERITY_DEF

#undef TRACE_SEV_X


enum trace_severity trace_runtime_control_set_default_min_sev(enum trace_severity sev __attribute__ ((unused))) {return TRACE_SEV_INVALID;}

