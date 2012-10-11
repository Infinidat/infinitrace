/*
   Copyright 2012 Yitzik Casapu of Indinidat
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
 */

#ifndef TRACE_SEV_DISPLAY_H_
#define TRACE_SEV_DISPLAY_H_


/* Define ANSI color patterns */
#include "colors.h"
#define TRACE_SEV_DEBUG_DISPLAY_COLOR  WHITE
#define TRACE_SEV_INFO_DISPLAY_COLOR   GREEN_B
#define TRACE_SEV_WARN_DISPLAY_COLOR   YELLOW_B
#define TRACE_SEV_ERR_DISPLAY_COLOR    RED_B
#define TRACE_SEV_FATAL_DISPLAY_COLOR  RED_B


/* Define display names for the severities. This can be used to achieve uniform width  */
#define TRACE_SEV_DEBUG_DISPLAY_STR "DBG "
#define TRACE_SEV_INFO_DISPLAY_STR  "INFO"
#define TRACE_SEV_WARN_DISPLAY_STR  "WARN"
#define TRACE_SEV_ERR_DISPLAY_STR   "ERR "
#define TRACE_SEV_FATAL_DISPLAY_STR "FATAL"


#endif /* TRACE_SEV_DISPLAY_H_ */
