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

#include "trace_lib.h"
#include "trace_user.h"

void REPR()
{
}

void DEBUG()
{
}

void ERR()
{
}

void INFO()
{
}

void WARN()
{
}

void FATAL()
{
}

/* Variabled for monitoring trace run duration */
const unsigned trace_duration_thresholds_ms[] = {1<<31};  /* Note: Should be in ascending order */
const unsigned trace_duration_thresholds_count = 1;
unsigned trace_duration_counters[1];

void trace_runtime_control_set_default_min_sev(enum trace_severity sev __attribute__ ((unused))) {}

