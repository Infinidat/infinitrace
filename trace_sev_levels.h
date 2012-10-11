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

#define TRACE_SEVERITY_DEF       \
     TRACE_SEV_X(2, DEBUG)       \
     TRACE_SEV_X(3, INFO)        \
     TRACE_SEV_X(4, WARN)        \
     TRACE_SEV_X(5, ERR)         \
     TRACE_SEV_X(6, FATAL)       \

enum trace_severity {
	TRACE_SEV_INVALID = 0,
	TRACE_SEV_FUNC_TRACE = 1,

#define TRACE_SEV_X(num, name) \
	TRACE_SEV_##name  = num,

TRACE_SEVERITY_DEF

#undef TRACE_SEV_X

	TRACE_SEV__COUNT,
	TRACE_SEV__MIN = TRACE_SEV_INVALID + 1,
	TRACE_SEV__MAX = TRACE_SEV__COUNT - 1
};

#endif /* TRACE_SEV_LEVELS_H_ */
