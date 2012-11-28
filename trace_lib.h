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

/* Supporting functions and data structures used by the trace code that that ccwrap.py injects into the source files */

#ifndef __TRACE_LIB_H__
#define __TRACE_LIB_H__

#ifdef __cplusplus
extern "C" {
#endif

#define TRACE_SHM_ID "_trace_shm_"
#define TRACE_DYNAMIC_SUFFIX "_dynamic_trace_data"
#define TRACE_STATIC_SUFFIX  "_static_trace_metadata"
/* Format strings with a %d placeholder for the pid */
#define TRACE_DYNAMIC_DATA_REGION_NAME_FMT TRACE_SHM_ID "%d" TRACE_DYNAMIC_SUFFIX
#define TRACE_STATIC_DATA_REGION_NAME_FMT  TRACE_SHM_ID "%d" TRACE_STATIC_SUFFIX


#include "trace_clock.h"
#include "macros.h"
#include <stdlib.h>
#include <sys/types.h>
#ifdef __repr__
#undef __repr__
#endif

/* Modify __repr__ method declarations and definitions to use the argument list required by the trace runtime. */
#define __repr__ _trace_represent( \
		unsigned int *__buf_left, unsigned char **__typed_buf, \
		struct trace_record* __records, unsigned int& __rec_idx, unsigned int& __records_array_len)

extern struct trace_buffer *current_trace_buffer;

/* Identifiers that are created by the linker script (see ldwrap.py) and mark the beginning and end of data-structure arrays inserted
 * by the instrumentation mechanism */
extern struct trace_log_descriptor __static_log_information_start;
extern struct trace_log_descriptor __static_log_information_end;
extern struct trace_type_definition *__type_information_start;


/* Used to control at runtime what data will be written to the trace */
struct trace_runtime_control {
	enum trace_severity default_min_sev; /* Minimum severity for reporting. Per-subsystem definitions take precedence over it */
	int  subsystem_range[2];
	enum trace_severity *thresholds;
	unsigned initial_records_per_trace;
	unsigned records_array_increase_factor;
};

/* An interface that the traced process can use at runtime to limit the severity of trace messages that will
 * be written to shared memory. */
extern const struct trace_runtime_control *const p_trace_runtime_control;

static inline enum trace_severity trace_runtime_control_get_default_min_sev(void)
{
	return p_trace_runtime_control->default_min_sev;
}
/* Set the default severity threshold which can be overridden for the current thread */
enum trace_severity trace_runtime_control_set_default_min_sev(enum trace_severity sev);

/* Reset all per-subsystem thresholds and set the range of allowed subsystem IDs */
int trace_runtime_control_set_subsystem_range(int low, int high);

int trace_runtime_control_set_sev_threshold_for_subsystem(int subsystem_id, enum trace_severity sev);
static inline enum trace_severity trace_runtime_control_get_sev_threshold_for_subsystem(int subsystem_id)
{
	return (NULL == p_trace_runtime_control->thresholds) ? TRACE_SEV_INVALID :
			p_trace_runtime_control->thresholds[subsystem_id - p_trace_runtime_control->subsystem_range[0]];
}

int trace_runtime_control_configure_buffer_allocation(unsigned initial_records_per_trace, unsigned records_array_increase_factor);

/* Allow the global default severity threshold to be overridden for the current thread by setting trace_thread_severity_threshold
 * to a value other than TRACE_SEV_INVALID */
extern __thread enum trace_severity trace_thread_severity_threshold;

/* Function call nesting level for function trace display */
extern __thread unsigned short trace_current_nesting;

/*** Supporting inline functions used by the trace code that that ccwrap.py injects into the source files ***/

static inline void trace_increment_nesting_level(void)
{
    trace_current_nesting++;
}

static inline void trace_decrement_nesting_level(void)
{
    trace_current_nesting--;
}

static inline unsigned short trace_get_nesting_level(void)
{
    return trace_current_nesting;
}

/*** Data-structures used in the per traced process shared-memory area where traces are written at runtime. ***/

/* Data that are modified as records are written and read */
struct trace_records_mutable_metadata {
	/* Whenever a thread in the traced process wants to write records, it atomically increments this value by the number of records it
	 * wants to write, thus reserving them and guaranteeing that no other thread could reserve them. */
	trace_atomic_t current_record;

	volatile unsigned int records_silently_discarded;
	volatile unsigned int records_with_invalid_sev;

	/* Once a record has been written next_committed_record is updated atomically. */
	trace_atomic_t last_committed_record;

	volatile unsigned int records_misplaced;

	/* Last record time-stamp that was written by the dumper. */
	trace_ts_t latest_flushed_ts;
};


/* Data that are initialized by the traced process at its initialization and not modified afterwards  */
struct trace_records_immutable_metadata {
	unsigned int max_records;		/* The number of trace records in the area */

	/* A mask where all the bits used to represent max_records above are set. */
	unsigned int max_records_mask;

	/* The smallest power of 2 that is greater than the number of records */
	unsigned int max_records_shift;

	/* A bit mask representing the severity levels that may be found in this set of records */
	unsigned int severity_type;
};

struct trace_records {
	struct trace_records_immutable_metadata imutab;
	volatile struct trace_records_mutable_metadata mutab;
	struct trace_record records[TRACE_RECORD_BUFFER_RECS];
};


struct trace_buffer {
    pid_t pid;
    union {
        struct trace_records _all_records[TRACE_BUFFER_NUM_RECORDS];
        struct {
            struct trace_records _debug;
            struct trace_records _other;
            struct trace_records _funcs;
        } records;
    } u;
};

/* Runtime support functions used by the auto-generated code inserted during trace instrumentation. Using them otherwise is not recommended, as they may change. */

/* Fill-in some of the record fields (termination, severity, pid, tid, timestamp and generation) and write them as a contiguous sequence. */
void trace_commit_records(
		struct trace_record *source_records,
		size_t n_records,
		enum trace_severity severity);

/* Handle allocation of a temporary array to hold the records in case the amount of records allocated on the stack is insufficient */
struct trace_record *trace_realloc_records_array(struct trace_record *const records, unsigned int* n_records);
void trace_free_records_array();

#ifdef __cplusplus
}
#endif
#endif /* __TRACE_LIB_H__ */

