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

#include "trace_defs.h"
#include "trace_macros.h"
#include <stdlib.h>
#include <sys/types.h>
#include <stdint.h>

#ifdef __repr__
#undef __repr__
#endif

/* Modify __repr__ method declarations and definitions to use the argument list required by the trace runtime. */
#define __repr__ TRACE_REPR_INTERNAL_METHOD_NAME ( \
		unsigned char*& __typed_buf         __attribute__((unused)), \
		struct trace_record* __records      __attribute__((unused)), \
		unsigned int& __rec_idx             __attribute__((unused)), \
		unsigned int& __records_array_len   __attribute__((unused)))

/*
 * Provide a way to produce the representation of a C++ object to which we have a pointer, that guarantees that the __repr__ function of
 * the pointer's class, as determined at compile-time, is called, irrespective of the actual class of the object that is being pointed to, which may have
 * overridden __repr__ with a custom implementation.
 * In order to achieve this, call the macro __repr_statically_bound_proxy_gen__ with the class name as argument in the public section of the class declaration.
 * Then, when you have a pointer to the an object and wish to produce its representation, call the method __repr_statically_bound_proxy__() .
 * Notes:
 *   This only makes sense when __repr__ is defined as virtual
 *   For this to work, the __repr__ method of your class must be declared as const.
 * */
#define __repr_statically_bound_proxy_gen__(cls)             \
    class __ ## cls ## _repr_statically_bound_proxy__ {      \
        const cls *const p;                                  \
    public:                                                  \
        __ ## cls ## _repr_statically_bound_proxy__(const cls *_p) : p(_p) {}               \
        void __repr__ const                                                                 \
        { p-> cls :: TRACE_REPR_INTERNAL_METHOD_NAME (__typed_buf, __records, __rec_idx, __records_array_len);   \
        return;                                                                             \
        /* The instrumentor expects a call to REPR() so we trick it */                      \
        /* coverity[deadcode] */                                                            \
        TRACE_REPR_CALL_NAME (); }                                                          \
    };                                                                                      \
    __ ## cls ## _repr_statically_bound_proxy__ __repr_statically_bound_proxy__() const { return __ ## cls ## _repr_statically_bound_proxy__(this); }


extern struct trace_buffer *current_trace_buffer;

/* Identifiers that are created by the linker script (see ldwrap.py) and mark the beginning and end of data-structure arrays inserted
 * by the instrumentation mechanism */
extern struct trace_log_descriptor __static_log_information_start[];
extern struct trace_log_descriptor __static_log_information_end[];
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

	/* A counter of the total number of (not necessarily consecutive) records written */
	trace_atomic_t num_records_written;

	volatile unsigned int records_silently_discarded;
	volatile unsigned int records_with_invalid_sev;

	/* The latest record in relation to which all prior records can be assumed to be committed.
	 * Note that in practice there could be cases when prior records have not yet been committed, and they remain to be resolved. */
	trace_atomic_t last_committed_record;

	/* Next record to be written by the dumper. */
	trace_atomic_t next_flush_record;

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

#define TRACE_BUFFER_NUM_RECORDS (4)  /* The number of trace buffers per traced process */

#define IS_PWR_OF_2(x) (0 == ((x) & ((x) - 1)))

#define TRACE_DEFAULT_RECORD_BUFFER_RECS 0x100000

#ifndef TRACE_RECORD_BUFFER_RECS
#define TRACE_RECORD_BUFFER_RECS  TRACE_DEFAULT_RECORD_BUFFER_RECS
#endif

#if (!IS_PWR_OF_2(TRACE_RECORD_BUFFER_RECS))
#error "TRACE_RECORD_BUFFER_RECS is not a power of 2"
#endif

#ifndef TRACE_RECORD_BUFFER_FUNCS_RECS
#define TRACE_RECORD_BUFFER_FUNCS_RECS TRACE_RECORD_BUFFER_RECS
#elif (!IS_PWR_OF_2(TRACE_RECORD_BUFFER_FUNCS_RECS))
#error "TRACE_RECORD_BUFFER_FUNCS_RECS is not a power of 2"
#endif

#undef IS_PWR_OF_2


struct trace_records {
	struct trace_records_immutable_metadata imutab;
	volatile struct trace_records_mutable_metadata mutab;
	struct trace_record records[TRACE_RECORD_BUFFER_RECS];
};


struct trace_buffer {
    pid_t pid;
    int n_record_buffers;
    unsigned buffer_indices[TRACE_SEV__COUNT];
    union {
        struct trace_records _all_records[TRACE_BUFFER_NUM_RECORDS];
        struct {
            struct trace_records _debug;
            struct trace_records _above_info;
            struct trace_records _other;
            struct trace_records _funcs;
        } records;
    } u;
};


/* Functions and data structures for retrieving the latest error of the current thread */

struct trace_internal_err_info {
    trace_ts_t  ts;
    unsigned    log_id;
    int         err_num;
};

const struct trace_internal_err_info *trace_internal_err_get_last(void);
void trace_internal_err_clear(void);

/* Runtime support functions used by the auto-generated code inserted during trace instrumentation. Using them otherwise is not recommended, as they may change. */

unsigned char *trace_copy_vstr_to_records(struct trace_record **records, unsigned *rec_idx, unsigned *records_array_len, unsigned char *typed_buf, const char *src);

unsigned char *trace_copy_scalar_to_records(struct trace_record **records, unsigned *rec_idx, unsigned *records_array_len, unsigned char *typed_buf, const unsigned char *src, unsigned len);

void trace_clear_record_remainder(struct trace_record *records, unsigned rec_idx, unsigned char *typed_buf);

/* Fill-in some of the record fields (termination, severity, pid, tid, timestamp and generation) and write them as a contiguous sequence. */
void trace_commit_records(
		struct trace_record *source_records,
		size_t n_records,
		enum trace_severity severity);

/* Handle allocation of a temporary array to hold the records in case the amount of records allocated on the stack is insufficient */
struct trace_record *trace_realloc_records_array(struct trace_record *const records, unsigned int* n_records);
void trace_free_records_array();

/* Advance the index to the record array, increasing the array itself if necessary */
static inline void trace_advance_record_array(struct trace_record **records, unsigned *rec_idx, unsigned *records_array_len)
{
	if (++ *rec_idx >= *records_array_len) {
		*records = trace_realloc_records_array(*records, records_array_len);
		*rec_idx = (*records_array_len - 1 >= *rec_idx) ? *rec_idx : *records_array_len - 1;
	}
}

/* Set errno for the thread to 0 and return the old errno value */
int trace_internal_err_clear_errno(void);

/* If errno is not 0, capture information about the error */
void trace_internal_err_record_if_necessary(int saved_errno, const struct trace_record *header);

#ifdef __cplusplus
}
#endif
#endif /* __TRACE_LIB_H__ */

