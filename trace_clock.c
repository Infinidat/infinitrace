/*
 * trace_clock.c
 *
 *  Created on: Oct 29, 2012
 *      Author: yitzikc
 */

#include <time.h>
#include "trace_clock.h"

static trace_ts_t trace_get_nsec_from_clk(clockid_t clk_id)
{
	struct timespec now;
	int rc = clock_gettime(clk_id, &now);
	if (0 != rc) {
		return (trace_ts_t) -1;
	}

	return now.tv_nsec + 1000000000ULL * now.tv_sec;
}

trace_ts_t trace_get_nsec(void)
{
     return trace_get_nsec_from_clk(CLOCK_REALTIME);
}

trace_ts_t trace_get_nsec_monotonic(void)
{
	return trace_get_nsec_from_clk(CLOCK_MONOTONIC);
}
