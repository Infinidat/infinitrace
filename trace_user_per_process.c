/*
 * trace_user_per_process.c
 * Trace Runtime support routines and data structures that should have a single instance in each traced process
 *
 *  Created on: Nov 20, 2013
 *  Original Author: Yotam Rubin, 2012
 *  Maintainer:      Yitzik Casapu, Infinidat
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
 */


#include "platform.h"

#include <errno.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sched.h>
#include <limits.h>
#include <emmintrin.h>


#include "trace_macros.h"
#include "trace_lib_internal.h"
#include "trace_user.h"
#include "min_max.h"
#include "trace_metadata_util.h"
#include "trace_shm_util.h"
#include "trace_clock.h"
#include "trace_proc_util.h"
#include "bool.h"
#include "file_naming.h"
#include "halt.h"




/* Global per process/thread data structures */
struct trace_buffer *current_trace_buffer = NULL;
__thread unsigned short trace_current_nesting;
static trace_module_id_t num_modules = 0;


__thread struct trace_thresholds trace_thread_thresholds = {
        .min_sev = TRACE_SEV_INVALID,
        .wait_timeout_us = TRACE_RUNTIME_USE_GLOBAL_DEFAULT,
        .free_ppm_stop_trace_threshold = TRACE_RUNTIME_USE_GLOBAL_DEFAULT,
        .min_stop_trace_sev = TRACE_SEV_INVALID,
};

static __thread pid_t tid_cache = 0;

static inline void __attribute__((unused)) __compile_time_checks__(void)
{
    TRACE_COMPILE_TIME_ASSERT_EQ(TRACE_RECORD_SIZE, sizeof(struct trace_record));
    TRACE_COMPILE_TIME_ASSERT_EQ(TRACE_RUNTIME_USE_GLOBAL_DEFAULT, TRACE_SEV_INVALID);
    TRACE_COMPILE_TIME_ASSERT_IS_NON_ZERO(TRACE_SEV_INVALID < TRACE_SEV__MIN);
    TRACE_COMPILE_TIME_ASSERT_IS_NON_ZERO(TRACE_SEV__COUNT  > TRACE_SEV__MAX);

    /* Check that the bit masks allocated to store module ids is large enough */
    TRACE_COMPILE_TIME_ASSERT_IS_NON_ZERO(TRACE_MODULE_ID_MAX < CHAR_BIT * sizeof(trace_module_id_allocation_mask_t));
}

trace_module_id_t trace_module_id_alloc(void)
{
    const trace_module_id_t  mod_id = __sync_fetch_and_add(&num_modules, 1);
    TRACE_ASSERT(mod_id <= TRACE_MODULE_ID_MAX);
    return mod_id;
}

/* Runtime support functions for obtaining information from the system */
static trace_pid_t trace_get_tid(void)
 {
   if (! tid_cache) {
       tid_cache = syscall(__NR_gettid);
   }
    return (trace_pid_t) tid_cache;
}

static void invalidate_tid_cache(void)
{
    tid_cache = 0;
}

static trace_pid_t trace_get_pid(void)
{
    /* No use doing our own caching for process-id, since glibc already does it for us in a fork-safe way (see the man page) */
    return (trace_pid_t) getpid();
}


static struct trace_runtime_control runtime_control =
{
    .default_thresholds = {
            .min_sev = TRACE_SEV_INVALID,
            .wait_timeout_us = TRACE_RUNTIME_WAIT_FOREVER,
            .free_ppm_stop_trace_threshold = 1024,
            .min_stop_trace_sev = TRACE_SEV__COUNT,
    },
    .subsystem_range = {0, 0},
    .subsystem_thresholds = NULL,
    .initial_records_per_trace = 64,
    .records_array_increase_factor = 3
};

const struct trace_runtime_control *const p_trace_runtime_control = &runtime_control;

enum trace_severity trace_runtime_control_set_default_min_sev(enum trace_severity sev)
{
    const enum trace_severity prev = runtime_control.default_thresholds.min_sev;
    runtime_control.default_thresholds.min_sev = sev;
    return prev;
}

int trace_runtime_control_set_sev_threshold_for_subsystem(int subsystem_id, enum trace_severity sev)
{
    if ((NULL == runtime_control.subsystem_thresholds) ||
        (subsystem_id < runtime_control.subsystem_range[0]) ||
        (subsystem_id > runtime_control.subsystem_range[1])) {
        errno = EINVAL;
        return -1;
    }

    runtime_control.subsystem_thresholds[subsystem_id - runtime_control.subsystem_range[0]].min_sev = sev;
    return 0;
}

void trace_runtime_control_free_thresholds(void) {
    if (NULL != runtime_control.subsystem_thresholds) {
        void *const thresholds = runtime_control.subsystem_thresholds;
        runtime_control.subsystem_thresholds = NULL;
        runtime_control.subsystem_range[0] = runtime_control.subsystem_range[1] = 0;
        free(thresholds);
    }
}

int trace_runtime_control_set_subsystem_range(int low, int high)
{
    if (high < low) {
        errno = EINVAL;
        return -1;
    }

    struct trace_thresholds *const subsystem_thresholds = calloc(high - low + 1, sizeof(runtime_control.subsystem_thresholds[0]));
    if (NULL == subsystem_thresholds) {
        return -1;
    }

    trace_runtime_control_free_thresholds();

    runtime_control.subsystem_range[0] = low;
    runtime_control.subsystem_range[1] = high;
    runtime_control.subsystem_thresholds = subsystem_thresholds;
    return 0;
}

static __thread struct trace_internal_err_info internal_err_info = {
        .ts         = 0,
        .log_id     = 0,
        .module_id  = 0,
        .err_num    = 0,
};

const struct trace_internal_err_info *trace_internal_err_get_last(void)
{
    return &internal_err_info;
}

void trace_internal_err_clear(void)
{
    memset(&internal_err_info, 0, sizeof(internal_err_info));
}

int trace_internal_err_clear_errno(void)
{
    const int saved_errno = internal_err_info.err_num;
    internal_err_info.err_num = 0;
    return saved_errno;
}

void trace_internal_err_record_if_necessary(int saved_errno, const struct trace_record *header)
{
    if (__builtin_expect(0 == internal_err_info.err_num, TRUE)) {
        internal_err_info.err_num = saved_errno;
    }
    else {
        if (NULL != header) {
            internal_err_info.ts = header->ts;
            internal_err_info.module_id = header->module_id;
            internal_err_info.log_id = (header->rec_type == TRACE_REC_TYPE_TYPED) ? header->u.typed.log_id : (trace_log_id_t) -1;
        }
        else {
            internal_err_info.ts = 0;
            internal_err_info.module_id = 0;
            internal_err_info.log_id = 0;
        }
    }
}

/* Runtime support functions called when writing traces to shared-memory */

int trace_runtime_control_configure_buffer_allocation(unsigned initial_records_per_trace, unsigned records_array_increase_factor)
{
    if ((initial_records_per_trace < 1) || (records_array_increase_factor < 2)) {
        internal_err_info.err_num = EINVAL;
        return -1;
    }

    runtime_control.initial_records_per_trace     = initial_records_per_trace;
    runtime_control.records_array_increase_factor = records_array_increase_factor;
    return 0;
}

static int trace_runtime_control_set_overwrite_protection_impl(
        unsigned stop_threshold_ppm, enum trace_severity stop_threshold_sev, unsigned wait_timeout_us, struct trace_thresholds *thresholds, struct trace_thresholds *old_thresholds)
{
    if (stop_threshold_ppm >= TRACE_BPPM_BASE) {
        errno = EINVAL;
        return -1;
    }

    if (NULL != old_thresholds) {
        memcpy(old_thresholds, thresholds, sizeof(*old_thresholds));
    }

    thresholds->free_ppm_stop_trace_threshold = stop_threshold_ppm;
    thresholds->min_stop_trace_sev = stop_threshold_sev;
    thresholds->wait_timeout_us = wait_timeout_us;
    return 0;
}

int trace_runtime_control_set_overwrite_protection(unsigned stop_threshold_ppm, enum trace_severity stop_threshold_sev, unsigned wait_timeout_us, struct trace_thresholds *old_thresholds)
{
    return trace_runtime_control_set_overwrite_protection_impl(stop_threshold_ppm, stop_threshold_sev, wait_timeout_us, &(runtime_control.default_thresholds), old_thresholds);
}

int trace_runtime_control_set_thread_overwrite_protection(unsigned stop_threshold_ppm, enum trace_severity stop_threshold_sev, unsigned wait_timeout_us, struct trace_thresholds *old_thresholds)
{
    return trace_runtime_control_set_overwrite_protection_impl(stop_threshold_ppm, stop_threshold_sev, wait_timeout_us, &trace_thread_thresholds, old_thresholds);
}

void trace_runtime_control_load_thread_overwrite_protection(const struct trace_thresholds *thresholds, struct trace_thresholds *old_thresholds)
{
    if (NULL != old_thresholds) {
        memcpy(old_thresholds, &trace_thread_thresholds, sizeof(trace_thread_thresholds));
    }

    if (NULL != thresholds) {
        memcpy(&trace_thread_thresholds, thresholds, sizeof(trace_thread_thresholds));
    }
}

static struct trace_records *trace_get_records(enum trace_severity severity)
{
    TRACE_ASSERT((TRACE_SEV_INVALID != severity) && (severity < TRACE_SEV__COUNT));
    const int rec_idx = current_trace_buffer->buffer_indices[severity];
    TRACE_ASSERT(rec_idx < current_trace_buffer->n_record_buffers);
    return current_trace_buffer->u._all_records + rec_idx;
}

static trace_generation_t trace_get_generation(trace_record_counter_t record_num, const struct trace_records_immutable_metadata *imutab)
{
    return (trace_generation_t)(record_num >> imutab->max_records_shift);
}

static unsigned bytes_left_in_buf(const struct trace_record *records, unsigned rec_idx, const unsigned char *typed_buf)
{
    const unsigned bytes_left = records[rec_idx].u.payload + TRACE_RECORD_PAYLOAD_SIZE - typed_buf;
    TRACE_ASSERT(bytes_left <= TRACE_RECORD_PAYLOAD_SIZE);  /* Check for typed_buf pointing outside the buffer */
    return bytes_left;
}


unsigned char *trace_copy_vstr_to_records(struct trace_record **records, unsigned *rec_idx, unsigned *records_array_len, unsigned char *typed_buf, const char *src)
{
    const unsigned char CONTINUATION_MASK = 0x80;
    unsigned bytes_left = bytes_left_in_buf(*records, *rec_idx, typed_buf);

    if (NULL == src) {  /* Treat NULL string arguments like printf() and friends do */
        /* Allocate a sufficiently large array for the string to avoid Coverity complaints about out of bounds access by memchr() */
        static const char null_str[TRACE_RECORD_PAYLOAD_SIZE] = "(null)";
        src = null_str;
    }

    do {
        if (0 == bytes_left) {
            trace_advance_record_array(records, rec_idx, records_array_len);
            typed_buf = (*records)[*rec_idx].u.payload;
            bytes_left = TRACE_RECORD_PAYLOAD_SIZE;
        }

        unsigned copy_size;
        const char *end = memchr(src, '\0', bytes_left);
        if (NULL != end) { /* The remaining length of the string can fit in the buffer */
            copy_size = end - src;
            TRACE_ASSERT(copy_size < bytes_left);
            typed_buf[0] = 0;
        }
        else {
            copy_size = bytes_left - 1;
            typed_buf[0] = CONTINUATION_MASK;
            TRACE_ASSERT(src[copy_size]);
        }

        TRACE_ASSERT(copy_size < CONTINUATION_MASK);

        typed_buf[0] |= copy_size;
        ++typed_buf;
        memcpy(typed_buf, src, copy_size);

        src += copy_size;
        typed_buf += copy_size;
        bytes_left -= (1 + copy_size);

    } while(*src);

    /* Make sure we're not allocating a new record needlessly */
    TRACE_ASSERT(bytes_left < TRACE_RECORD_PAYLOAD_SIZE);

    return typed_buf;
}

unsigned char *trace_copy_scalar_to_records(struct trace_record **records, unsigned *rec_idx, unsigned *records_array_len, unsigned char *typed_buf, const unsigned char *src, unsigned len)
{
    TRACE_ASSERT(len < TRACE_RECORD_PAYLOAD_SIZE);

    unsigned bytes_left = bytes_left_in_buf(*records, *rec_idx, typed_buf);
    const unsigned copy_size = MIN(bytes_left, len);
    memcpy(typed_buf, src, copy_size);

    if (copy_size < len) {
        trace_advance_record_array(records, rec_idx, records_array_len);
        const unsigned second_copy_size = len - copy_size;
        unsigned char *const second_copy_start = (*records)[*rec_idx].u.payload;

        memcpy(second_copy_start, src + copy_size, second_copy_size);
        typed_buf = second_copy_start + second_copy_size;
    }
    else {
        typed_buf += len;
    }

    return typed_buf;
}

void trace_clear_record_remainder(struct trace_record *records, unsigned rec_idx, unsigned char *typed_buf)
{
    memset(typed_buf, TRACE_UNUSED_SPACE_FILL_VALUE, bytes_left_in_buf(records, rec_idx, typed_buf));
}

static void update_last_committed_record(struct trace_records *records, trace_record_counter_t new_index)
{
    trace_record_counter_t expected_value;
    trace_record_counter_t found_value = records->mutab.last_committed_record;

    /* Update records->mutab.last_committed_record to the index of the current record, taking care not to overwrite a larger value.
     * It's possible that another thread has increased records->mutab.last_committed_record between the last statement and this point so
     * occasionally we might have to repeat this more than once.  */
    do {
        expected_value = found_value;

        /* Forego the update if another thread has committed a later record */
#ifndef _LP64
#warning "The comparison below might cause anomalous behavior due to counter wrap-around on 32-bit platforms, please verify and test."
#endif
        if ((expected_value > new_index) && (expected_value < TRACE_RECORD_INVALID_COUNT)) {
            break;
        }

        found_value = __sync_val_compare_and_swap(
                &records->mutab.last_committed_record,
                expected_value,
                new_index);

        /* Make absolutely sure that no other thread has committed the same record that we were working on */
        TRACE_ASSERT(new_index != found_value);
    } while (found_value != expected_value);
}

/* Copy traces to the buffers using intrinsics that generate write-through memory access, reducing the likelihood cache coherency issues. */
static void copy_trace_record_wt(struct trace_record *target, const struct trace_record *src)
{

#define IS_MULTIPLE_OF_16(p) (0 == ((p) % 16))

#if (!IS_MULTIPLE_OF_16(TRACE_RECORD_SIZE))
#error Trace record size must be a multiple of 16, please fix!
#endif

#define IS_PTR_MULTIPLE_OF_16(p) IS_MULTIPLE_OF_16((uintptr_t) (p))

    TRACE_ASSERT(IS_PTR_MULTIPLE_OF_16(target) && IS_PTR_MULTIPLE_OF_16(src));

#undef IS_MULTIPLE_OF_16
#undef IS_PTR_MULTIPLE_OF_16

    TRACE_COMPILE_TIME_ASSERT_EQ(sizeof(__m128i), 16);
    const __m128i *const s = (const __m128i *) src;
    __m128i *const       t = (__m128i *) target;

    for (unsigned i = 0; i < TRACE_RECORD_SIZE / 16; i++) {
        _mm_stream_si128(t + i, s[i]);
    }
}

static trace_record_counter_t max_allowed_base_index(const struct trace_records *records, size_t n_records)
{
    const unsigned free_ppm_threshold =
            (trace_thread_thresholds.free_ppm_stop_trace_threshold > 0) ?
             trace_thread_thresholds.free_ppm_stop_trace_threshold :
             runtime_control.default_thresholds.free_ppm_stop_trace_threshold;
    const trace_record_counter_t min_required_free_recs =
            ((unsigned long long)free_ppm_threshold << records->imutab.max_records_shift) / TRACE_BPPM_BASE;
    return records->mutab.next_flush_record + records->imutab.max_records - min_required_free_recs - n_records;
}

static trace_record_counter_t allocate_records(struct trace_records *records, size_t n_records, enum trace_severity severity)
{
    trace_ts_t max_ts = 0;
    do {
        const trace_record_counter_t base_index = __sync_fetch_and_add(&(records->mutab.current_record), n_records);
        if (base_index <= max_allowed_base_index(records, n_records)) {
            return base_index;
        }

        /* Try to roll-back the allocation of records, to make them available to other threads with a possibly lower free space threshold.
         * Care should be taken in case another thread has advanced the counter in the meantime. */
        const trace_record_counter_t expected_base_index = base_index + n_records;
        while (__sync_val_compare_and_swap(&(records->mutab.current_record), expected_base_index, base_index) !=
                expected_base_index) {
            /* If another thread (presumably with a different free space threshold) has committed a record beyond ours,
             * there's no way to undo the taking of space, so we might as well write our traces */
            if (expected_base_index <= records->mutab.num_records_written) {
                return base_index;
            }
        }

        const enum trace_severity pause_threshold =
                (TRACE_SEV_INVALID != trace_thread_thresholds.min_stop_trace_sev) ? trace_thread_thresholds.min_stop_trace_sev : runtime_control.default_thresholds.min_stop_trace_sev;
        if (severity < pause_threshold) {
            break;
        }

        if (0 == max_ts) {
            const trace_ts_t timeout_us =
                    (0 != trace_thread_thresholds.wait_timeout_us) ?
                            trace_thread_thresholds.wait_timeout_us :
                            runtime_control.default_thresholds.wait_timeout_us;
            TRACE_COMPILE_TIME_ASSERT_EQ((typeof(trace_thread_thresholds.min_stop_trace_sev)) TRACE_RUNTIME_WAIT_FOREVER, \
                                         (typeof(timeout_us))                                 TRACE_RUNTIME_WAIT_FOREVER);
            max_ts = (TRACE_RUNTIME_WAIT_FOREVER != timeout_us) ? trace_get_nsec_monotonic() + TRACE_US * timeout_us : ULLONG_MAX;
        }

        sched_yield();

    } while (trace_get_nsec_monotonic() <= max_ts);

    internal_err_info.err_num = ENOSPC;
    return TRACE_RECORD_INVALID_COUNT;
}

void trace_commit_records(
        struct trace_record *source_records,
        size_t n_records,
        enum trace_severity severity)
{
    TRACE_ASSERT(n_records > 0);
    TRACE_ASSERT(NULL != source_records);
    TRACE_ASSERT(TRACE_SEV_INVALID != severity);

    struct trace_records *const records = trace_get_records(severity);
    TRACE_ASSERT((1U << severity) & records->imutab.severity_type);

    const trace_ts_t  ts = trace_get_nsec();
    source_records->ts = ts;  /* This field must be initialized even if we fail to allocate a record */
    source_records->termination = TRACE_TERMINATION_FIRST;
    source_records->severity    = TRACE_SEV_INVALID;
    struct trace_record *first_rec_in_buf = NULL;

    const trace_record_counter_t base_index = allocate_records(records, n_records, severity);
    if (__builtin_expect(TRACE_RECORD_INVALID_COUNT != base_index, TRUE)) {
        const trace_pid_t tid = trace_get_tid();
        const trace_pid_t pid = trace_get_pid();

        size_t i;
        for (i = 0; i < n_records; i++) {
            /* TODO: This could be a good place to pre-fetch the next trace record using e.g. __builtin_prefetch */

            source_records[i].pid = pid;
            source_records[i].tid = tid;
            source_records[i].rec_type = TRACE_REC_TYPE_TYPED;

            /* As an aid to debugging, store the physical record number in the nesting field, which is unused except for function traces. */
            if (severity > TRACE_SEV_FUNC_TRACE) {
                source_records[i].nesting = i;
            }

            const trace_record_counter_t record_index = base_index + i;
            source_records[i].generation = trace_get_generation(record_index, &records->imutab);
            struct trace_record *const target = records->records + (record_index & records->imutab.max_records_mask);
            if (0 == i) {
                first_rec_in_buf = target;
                TRACE_ASSERT(TRACE_SEV_INVALID == first_rec_in_buf->severity);
            }
            else {
                source_records[i].termination = 0;
                source_records[i].severity = severity;
                source_records[i].ts = ts;
            }

            if (n_records - 1 == i) {
                source_records[i].termination |= TRACE_TERMINATION_LAST;
            }

            copy_trace_record_wt(target, source_records + i);
        }

        /* Check that it is at least possible that all the records that were in the process of being written at the time were started have been written by now.
         * Note that the condition below doesn't guarantee that they have in fact been written. An algorithm that can ascertain that remains to be developed. */
        const trace_record_counter_t records_written = __sync_fetch_and_add(&records->mutab.num_records_written, n_records);
        if (records_written >= base_index) {
            update_last_committed_record(records, base_index + n_records - 1);
        }

        __sync_synchronize();
        first_rec_in_buf->severity = severity;
    }
    else {
        __sync_fetch_and_add(&(records->mutab.records_discarded_due_to_no_space), n_records);
    }

    trace_free_records_array();
}

/* Functions for managing memory allocations on the heap while writing traces. This is seldom required, only when the amount of memory allocated on the stack in order to produce the
 * trace is insufficient */

static __thread struct trace_record *trace_records_dynamic_array = NULL;

struct trace_record *trace_realloc_records_array(struct trace_record *const records, unsigned int *n_records)
{
    assert(runtime_control.records_array_increase_factor > 1);
    if (NULL == n_records) {
        internal_err_info.err_num = EFAULT;
        return NULL;
    }

    /* Verify that records is either a pointer obtained through a previous call to this function or NULL */
    const bool_t records_valid = (NULL == trace_records_dynamic_array) || (records == trace_records_dynamic_array);
    if ((*n_records < 1) || ! records_valid)  {
        internal_err_info.err_num = EINVAL;
        return NULL;
    }

    const size_t old_size = TRACE_RECORD_SIZE * *n_records;
    const size_t new_size = old_size * runtime_control.records_array_increase_factor;
    struct trace_record *new_records = realloc(trace_records_dynamic_array, new_size);

    if (NULL == new_records) {
        /* The old array could not be increased, but it is still valid */
        return (NULL != records) ? records : trace_records_dynamic_array;
    }

    if ((NULL != records) && (NULL == trace_records_dynamic_array)) {  /* The original data is in an array allocated on the stack */
        memcpy(new_records, records, old_size);
    }
    *n_records = new_size / TRACE_RECORD_SIZE;
    trace_records_dynamic_array = new_records;
    return new_records;
}

void trace_free_records_array()
{
    if (NULL != trace_records_dynamic_array) {
        free(trace_records_dynamic_array);
        trace_records_dynamic_array = NULL;
    }
}

int trace_finalize(void)
{
    int rc = trace_dynamic_log_buffers_unmap_if_necessary();
    trace_runtime_control_free_thresholds();
    rc |= trace_shm_delete_files(getpid());
    return rc;
}



int trace_buffers_reset_if_new_process(void)
{
    if (trace_has_processed_forked_since_init()) {
        num_modules = 0;
        return trace_dynamic_log_buffers_unmap_if_necessary();
    }

    return 0;
}


/* Support for forking traced processes */

static trace_module_id_t module_ids_allocated = 0;

static int child_proc_init(void)
{
    current_trace_buffer = NULL;
    invalidate_tid_cache();
    trace_module_id_t module_ids_pending = module_ids_allocated;
    while (module_ids_pending) {
        const unsigned mod_id = __builtin_ctz(module_ids_pending);

        trace_shm_name_buf parent_static_shm_name;
        const struct trace_shm_module_details parent_details = {
                .pid = getppid(),
                .module_id = mod_id,
        };
        TRACE_ASSERT(trace_generate_shm_name(parent_static_shm_name, &parent_details, TRACE_SHM_TYPE_STATIC_PER_PROCESS, FALSE) > 0);

        trace_shm_name_buf static_shm_name;
        const struct trace_shm_module_details details = {
                .pid = getpid(),
                .module_id = mod_id,
        };
        TRACE_ASSERT(trace_generate_shm_name(static_shm_name, &details, TRACE_SHM_TYPE_STATIC_PER_PROCESS, FALSE) > 0);

        if (trace_shm_duplicate(parent_static_shm_name, static_shm_name) < 0) {
            goto delete_static_shm;
        }

        module_ids_pending &= (! (1U << mod_id));
    }

    if (trace_dynamic_log_buffers_map(module_ids_allocated) < 0) {
        goto delete_static_shm;
    }

    return 0;

delete_static_shm:
    {
        const int saved_errno = errno;
        trace_shm_delete_files(getpid());
        TRACE_ASSERT(0 != saved_errno);
        errno = saved_errno;
        return -1;
    }
}

pid_t trace_fork(void)
{
    if (! trace_is_initialized()) {
        return fork();
    }

    module_ids_allocated = current_trace_buffer->module_ids_allocated;
    return trace_fork_with_child_init(child_proc_init, trace_shm_delete_files);
}


