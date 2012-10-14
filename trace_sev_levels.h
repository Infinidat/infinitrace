/***
Copyright 2012 Yitzik Casapu of Indinidat
   Sponsored by infinidat (http://infinidat.com)
   Adapted from code by Yotam Rubin <yotamrubin@gmail.com>

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

#ifndef TRACE_SEV_LEVELS_H_
#define TRACE_SEV_LEVELS_H_

/* Note: to customize Traces' levels for your own application, modify the TRACE_SEVERITY_DEF macro and the
 * display definitions in trace_sev_display.h
 * Also note that the numbers assigned must be contiguous and ascending, starting at TRACE_SEV__MIN */

/* A TRACE_SEVERITY_.._DEF macro is defined for every format version that changes the severity level mapping. When introducing a format
 * version that doesn't make any changes to severity level mappings, there's no need to define it for that level. */

#define TRACE_SEVERITY_0xA3_DEF       \
     TRACE_SEV_X(2, DEBUG)       \
     TRACE_SEV_X(3, TRIO)        \
     TRACE_SEV_X(4, INFO)        \
     TRACE_SEV_X(5, WARN)        \
     TRACE_SEV_X(6, ERR)         \
     TRACE_SEV_X(7, FATAL)       \

/* Backward compatibility defintions */
#define TRACE_SEVERITY_0xA1_DEF  \
     TRACE_SEV_X(2, DEBUG)       \
     TRACE_SEV_X(3, INFO)        \
     TRACE_SEV_X(4, WARN)        \
     TRACE_SEV_X(5, ERR)         \
     TRACE_SEV_X(6, FATAL)       \


#endif /* TRACE_SEV_LEVELS_H_ */
