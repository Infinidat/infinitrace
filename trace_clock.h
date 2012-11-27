/*
 * trace_clock.h
 *
 *  Created on: Oct 29, 2012
 ***
Copyright 2012 Indinidat Inc
Written by: Yitzik Casapu
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


#ifndef TRACE_CLOCK_H_
#define TRACE_CLOCK_H_

#include "trace_defs.h"

/* Constants for time durations.
 * Note: Using defines and not an enum, since enumerations with values too large to be represented using 32 bits are not portable */
#define TRACE_MS 	 (1000000LL)
#define TRACE_SECOND (TRACE_MS * 1000)
#define TRACE_MINUTE (TRACE_SECOND * 60)
#define TRACE_HOUR   (TRACE_MINUTE * 60)
#define TRACE_DAY    (TRACE_HOUR * 24)
#define TRACE_YEAR   (TRACE_DAY * 365)

trace_ts_t trace_get_nsec(void);
trace_ts_t trace_get_nsec_monotonic(void);

#endif /* TRACE_CLOCK_H_ */
