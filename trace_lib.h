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


#include "trace_defs.h"
#include "macros.h"
#include <sys/syscall.h>
#include <time.h>    
#include <string.h>

#ifdef __repr__
#undef __repr__
#endif
    
#define __repr__ _trace_represent(unsigned int *buf_left, struct trace_record *_record, struct trace_record **__record_ptr, unsigned char **typed_buf, enum trace_severity __severity)
#if !defined(_UNISTD_H) && defined(__linux__)
#ifdef __cplusplus     
    extern long int syscall (long int __sysno, ...) throw ();
#else
    extern long int syscall(long int __sysno, ...);
#endif
#endif    

#define _O_RDONLY	00000000   

extern struct trace_buffer *current_trace_buffer;

/* Identifiers that are created by the liner script (see ldwrap.py) and mark the beginning and end of data-structure arrays inserted
 * by the instrumentation mechanism */
extern struct trace_log_descriptor __static_log_information_start;
extern struct trace_log_descriptor __static_log_information_end;
extern struct trace_type_definition *__type_information_start;

/* Function call nesting level for function trace display */
extern __thread unsigned short trace_current_nesting; 

/* An interface that the traced process can use at runtime to limit the severity of trace messages that will
 * be written to shared memory. */
extern const struct trace_runtime_control *p_trace_runtime_control;

/* Set the default severity threshold which can be overridden for the current thread */
enum trace_severity trace_runtime_control_set_default_min_sev(enum trace_severity sev);

/* Reset all per-subsystem thresholds and set the range of allowed subsytem IDs */
int trace_runtime_control_set_subsystem_range(int low, int high);

int trace_runtime_control_set_sev_threshold_for_subsystem(int subsystem_id, enum trace_severity sev);
static inline enum trace_severity trace_runtime_control_get_sev_threshold_for_subsystem(int subsystem_id)
{
	if (NULL == p_trace_runtime_control->thresholds) {
		return TRACE_SEV_INVALID;
	}
	TRACE_ASSERT((subsystem_id >= p_trace_runtime_control->subsystem_range[0]) && (subsystem_id <= p_trace_runtime_control->subsystem_range[1]));
	return p_trace_runtime_control->thresholds[subsystem_id - p_trace_runtime_control->subsystem_range[0]];
}

/* Allow the global default severity threshold to be overridden for the current thread by setting trace_thread_severity_threshold
 * to a value other than TRACE_SEV_INVALID */
extern __thread enum trace_severity trace_thread_severity_threshold;

/*** Supporting inline functions used by the trace code that that ccwrap.py injects into the source files ***/

#ifdef __linux__

static inline unsigned short int trace_get_pid(void)
{
    static __thread int pid_cache = 0;
    if (pid_cache)
		return pid_cache;
	pid_cache = syscall(__NR_getpid);
	return pid_cache;
}
    
static inline unsigned short int trace_get_tid(void)
{
    static __thread int tid_cache = 0;
    if (tid_cache)
		return tid_cache;
	tid_cache = syscall(__NR_gettid);
	return tid_cache;
}
    
static inline trace_ts_t trace_get_nsec(void)
{
     struct timespec tv;
     clock_gettime(CLOCK_REALTIME, &tv);
     return ((unsigned long long) tv.tv_sec * 1000000000) + tv.tv_nsec;
}

#endif

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

static inline void set_current_trace_buffer_ptr(struct trace_buffer *trace_buffer_ptr)
{
    current_trace_buffer = trace_buffer_ptr;
}

static inline trace_generation_t trace_get_generation(trace_record_counter_t record_num, const struct trace_records_immutable_metadata *imutab)
{
	return (trace_generation_t)(record_num >> imutab->max_records_shift);
}

struct trace_record *trace_get_record(enum trace_severity severity, trace_generation_t *generation);
void trace_commit_record(struct trace_record *target_record, const struct trace_record *source_record, enum trace_severity severity);

#ifdef __cplusplus
}
#endif
#endif /* __TRACE_LIB_H__ */
