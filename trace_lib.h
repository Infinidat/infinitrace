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
    
#define __repr__ _trace_represent(unsigned int *buf_left, struct trace_record *_record, struct trace_record **__record_ptr, unsigned char **typed_buf)
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
void trace_runtime_control_set_default_min_sev(enum trace_severity sev);

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
    
#define trace_atomic_t int

static inline int trace_strnlen(const char *c, int l)
{
	int r = 0;

	while (*c  &&  l >= 0) {
		r++;
		c++;
		l--;
	}

	return r;
}

/*** Data-structures used in the per traced process shared-memory area where traces are written at runtime. ***/

/* Data that are modified as records are written and read */
struct trace_records_mutable_metadata {
	/* Whenever a thread in the traced process wants to write records, it atomically increments this value by the number of records it
	 * wants to write, thus reserving them and guaranteeing that no other thread could reserve them. */
	volatile trace_atomic_t current_record;
	/* padding to make sure that the data that is accessed atomically occupies a full cache line, thus not hindering anything else. */
	trace_atomic_t pad1;

	volatile unsigned int records_silently_discarded;
	volatile unsigned int records_with_invalid_sev;

	/* Once a record has been written next_committed_record is updated atomically. */
	volatile trace_atomic_t last_committed_record;
	trace_atomic_t pad2;

	volatile unsigned int records_misplaced;
	trace_atomic_t pad3;

	/* Last record time-stamp that was written by the dumper. */
	unsigned long long latest_flushed_ts;
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
            struct trace_records _funcs;
            struct trace_records _debug;
            struct trace_records _other;
        } records;
    } u;
};

static inline void set_current_trace_buffer_ptr(struct trace_buffer *trace_buffer_ptr)
{
    current_trace_buffer = trace_buffer_ptr;
}

static inline struct trace_records *trace_get_records(enum trace_severity severity)
{
	switch ((int)severity) {
	case TRACE_SEV_FUNC_TRACE:
		return &current_trace_buffer->u.records._funcs;

		/* TODO: Check why we are sometimes passed TRACE_SEV_INVALID when the instrumentor processes called to REPR, see ticket IBOX15-133
		 * For the time being we arbitrarily place them in the debug buffer. */
	case TRACE_SEV_INVALID:
	case TRACE_SEV_DEBUG:
		return &current_trace_buffer->u.records._debug;

	default:
		return &current_trace_buffer->u.records._other;
	}
}


static inline int trace_compare_generation(unsigned int a, unsigned int b)
{
	if (a >= 0xc0000000   &&  b < 0x40000000)
		return 1;
	if (b > a)
		return 1;
	if (b < a)
		return -1;
	return 0;
}


/* TODO: Consider allowing an option for lossless tracing. */
static inline struct trace_record *trace_get_record(enum trace_severity severity, unsigned int *generation)
{

	struct trace_record *record;
	unsigned int record_index;
	struct trace_records *records = trace_get_records(severity);

	/* To implement lossless mode: Make sure we don't overwrite data beyond 
	   records->imutab.latest_flush_ts */

    record_index = __sync_fetch_and_add(&records->mutab.current_record, 1);
    *generation = record_index >> records->imutab.max_records_shift;
    record_index &= records->imutab.max_records_mask;

	record = &records->records[record_index % TRACE_RECORD_BUFFER_RECS];
	return record;
}

#define TRACE_COPY_ADJACENT_RECORDS() struct trace_record adjacent[15]; memcpy((void *)adjacent, (const void *)(target_record - 7), sizeof(adjacent));


/* TODO: In this function we silently ignore many anomalous conditions. We should at the very least set-up conters for them. */
static inline void trace_commit_record(struct trace_record *target_record, const struct trace_record *source_record)
{
	struct trace_records *records = trace_get_records((enum trace_severity)(source_record->severity));

	/* If the target record already contains a newer record by another thread, silently discard the trace data. */
	if (trace_compare_generation(
			source_record->generation << records->imutab.max_records_shift,
			target_record->generation << records->imutab.max_records_shift) > 0) {
		__sync_fetch_and_add(&records->mutab.records_silently_discarded, 1);
		return;
	}
	/* Check if another thread had already committed the exact same record. */
	else if ((source_record->generation == target_record->generation) && (source_record->generation > 0)) {
		struct trace_records_mutable_metadata mu;
		memcpy(&mu, (const void *)&records->mutab, sizeof(mu));
		TRACE_COPY_ADJACENT_RECORDS();
		TRACE_ASSERT(0);
	}
	__builtin_memcpy(target_record, source_record, sizeof(*source_record));

	/* Normally we should never get TRACE_SEV_INVALID as severity, but this does happen. See the comment above in trace_get_records()
	 * for additional details. When this does happen we emulate the behavior that existed prior to the INFINIBOX-2506 fix, i.e. don't go
	 * beyond this point. */
	if (TRACE_SEV_INVALID == source_record->severity) {
		__sync_fetch_and_add(&records->mutab.records_with_invalid_sev, 1);
		return;
	}

	unsigned record_pos = target_record - records->records;

	/* Sometimes records are misplaced. This shouldn't happen but does.
	 * TODO: Write an algorithm that finds the right memory buffer in this case. */
	if (record_pos >= records->imutab.max_records) {
		__sync_fetch_and_add(&records->mutab.records_misplaced, 1);
		return;
	}

	trace_atomic_t new_index = (source_record->generation << records->imutab.max_records_shift) + record_pos;

	__sync_synchronize();

	trace_atomic_t expected_value;
	trace_atomic_t found_value;

	/* Update records->mutab.last_committed_record to the index of the current record, taking care not to overwrite a larger value.
	 * It's possible that another thread has increased records->mutab.last_committed_record between the last statement and this point so
	 * occasionally we might have to repeat this more than once.  */
	do {
		expected_value = records->mutab.last_committed_record;

		/* Forego the update if another thread has committed a later record */
		if (trace_compare_generation(new_index, expected_value) > 0)
			break;

		found_value = __sync_val_compare_and_swap(
				&records->mutab.last_committed_record,
				expected_value,
				new_index);

		/* Make absolutely sure that no other thread has committed the same record that we were working on */
		if ((new_index == found_value) && (0 != new_index)) {
			struct trace_records_mutable_metadata mu;
			memcpy(&mu, (const void *)&records->mutab, sizeof(mu));
			TRACE_COPY_ADJACENT_RECORDS();
			TRACE_ASSERT(0);
		}
	} while (found_value != expected_value);
}

#undef TRACE_COPY_ADJACENT_RECORDS

#ifdef __cplusplus
}
#endif
#endif /* __TRACE_LIB_H__ */
