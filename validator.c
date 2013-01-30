/*
 * validator.c
 *
 *  Created on: Oct 25, 2012
 *      Author: yitzikc
 */

#include <errno.h>
#include <assert.h>
#include <syslog.h>
#include <unistd.h>

#include "min_max.h"
#include "bool.h"
#include "trace_user.h"
#include "validator.h"

static inline void invalidate_record(struct trace_record *record)
{
	record->rec_type = TRACE_REC_TYPE_UNKNOWN;
}

static inline bool_t conditionally_invalidate_record(bool_t should_invalidate, struct trace_record *record)
{
	if (should_invalidate) {
		invalidate_record(record);
	}
	return should_invalidate;
}

#define QUIT_ON_UNRECOVERABLE_ERR(...)  { ERR(__VA_ARGS__); errno = EPROTO; return - __LINE__; }

int trace_typed_record_sequence_validator(struct trace_record *records, int n_records, unsigned flags, void *context __attribute__((unused)))
{
	int records_invalidated = 0;
	const bool_t fix_errors = (0 != (flags & TRACE_VALIDATOR_FIX_ERRORS));
	const bool_t check_pid_consistency = (0 == (flags & TRACE_VALIDATOR_SKIP_PID_CONSISTENCY_CHECK));

	/* Skip any trailing invalid records, so that we don't get the reference from any of these, which would lead to an error. */
	for (; (n_records >= 1) && (TRACE_REC_TYPE_UNKNOWN == records[n_records - 1].rec_type); n_records--)
	    ;

	const struct trace_record *end = records + n_records;
	const struct trace_record *earliest_invalidated = NULL;
	if ((n_records >= 1) && (TRACE_REC_TYPE_TYPED != records[n_records - 1].rec_type)) {
	    QUIT_ON_UNRECOVERABLE_ERR("Got unexpected type at last record", n_records, (enum trace_rec_type)(records[n_records - 1].rec_type), end)
	}

	if (n_records >= 2) {
		const unsigned generation = records[n_records - 1].generation;
		const pid_t pid = records[n_records - 1].pid;
		for (struct trace_record *typed_rec = records + n_records - 2; typed_rec >= records; typed_rec--) {
			if (TRACE_REC_TYPE_TYPED != typed_rec->rec_type) {
				/* For some reason we sometimes get TRACE_REC_TYPE_UNKNOWN records. We'll ignore this for the time being ...  */
				if (TRACE_REC_TYPE_UNKNOWN != typed_rec->rec_type) {
				    QUIT_ON_UNRECOVERABLE_ERR("Got unexpected record type at pos",
				            typed_rec - end + n_records, (enum trace_rec_type)(typed_rec->rec_type), typed_rec->termination)
				}
				continue;
			}

			if (check_pid_consistency && (pid != typed_rec->pid))
			    QUIT_ON_UNRECOVERABLE_ERR("Got unexpected pid", typed_rec->pid, "instead of", pid)

			if (typed_rec->generation > generation) {
				/* This record got overrun before we copied it from the shared-memory buffer */
				conditionally_invalidate_record(fix_errors, typed_rec);
				records_invalidated++;
				earliest_invalidated = typed_rec;
				/* Also invalidate subsequent records until we find one that is marked as first, or records we have already invalidated. */
				for (struct trace_record *invalid_rec = typed_rec + 1;
					(invalid_rec < end) && !(invalid_rec->termination & TRACE_TERMINATION_FIRST) && (TRACE_REC_TYPE_UNKNOWN != invalid_rec->rec_type);
					invalid_rec++) {
					conditionally_invalidate_record(fix_errors, typed_rec);
					records_invalidated++;
				}
			}
			/* Note: sometimes we have records left-over from a previous generation,
			 * so we don't lower the generation threshold when we encounter an earlier generation. */
		}

		if (records_invalidated > 0) {
		    WARN("Had to invalidate records", records_invalidated, n_records, pid, generation,
		            "Earliest invalidated at index", earliest_invalidated - records, "of generation", earliest_invalidated->generation);
			syslog(LOG_USER|LOG_DEBUG, "Had to invalidate %d of %d records from pid %d, last rec generation=%u, earliest generation=%u, earliest invalidated at offset %ld with generation %u",
					records_invalidated, n_records, pid, records[n_records - 1].generation, generation, earliest_invalidated - records, earliest_invalidated->generation);
		}
	}

	return records_invalidated;

}

int trace_dump_validator(struct trace_record *records, int n_records, unsigned flags, void *context)
{
	const struct trace_record *end = records + n_records;

	switch (records->rec_type) {
	case TRACE_REC_TYPE_DUMP_HEADER:
		records++;
		break;

	default:
		break;
	}

	int records_invalidated = 0;
	while (records < end) {
		if (TRACE_REC_TYPE_BUFFER_CHUNK != records->rec_type) /* Not well-formed dump data */
		    QUIT_ON_UNRECOVERABLE_ERR("Could not find chunk header, got instead at pos", records - end + n_records, (enum trace_rec_type)(records->rec_type))

		unsigned chunk_records = MIN(records->u.buffer_chunk.records, end - records - 1);
		if (chunk_records < 1)
		    QUIT_ON_UNRECOVERABLE_ERR("Invalid chunk header with", chunk_records)

		int rc = trace_typed_record_sequence_validator(records + 1, chunk_records, flags, context);
		if (rc < 0) {
			return rc;
		}

		records_invalidated += rc;

		/* Add the count of invalidates records to the previously computed lost record count */
		if (flags & TRACE_VALIDATOR_FIX_ERRORS) {
			records->u.buffer_chunk.lost_records += rc;
		}

		records += (chunk_records + 1);
		assert(records <= end);
	}

	return records_invalidated;
}
