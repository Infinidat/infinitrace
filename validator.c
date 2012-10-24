/*
 * validator.c
 *
 *  Created on: Oct 25, 2012
 *      Author: yitzikc
 */

#include <errno.h>
#include <syslog.h>

#include "min_max.h"
#include "validator.h"

int trace_typed_record_sequence_validator(struct trace_record *records, int n_records, bool_t fix_errors, void *context __attribute__((unused)))
{
	int records_invalidated = 0;
	const struct trace_record *end = records + n_records;

	if ((n_records >= 1) && (TRACE_REC_TYPE_TYPED != records[n_records - 1].rec_type) && (TRACE_REC_TYPE_UNKNOWN != records[n_records - 1].rec_type)) {
		/* syslog(LOG_USER|LOG_ERR, "Expected typed record and got instead %u at pos %ld",
				records->rec_type, records - end + n_records); */
		errno = EPROTO;
		return - __LINE__;
	}

	if (n_records >= 2) {
		unsigned generation = records[n_records - 1].generation;
		for (struct trace_record *typed_rec = records + n_records - 2; typed_rec >= records; typed_rec--) {
			if (TRACE_REC_TYPE_TYPED != typed_rec->rec_type) {
				/* For some reason we sometimes get TRACE_REC_TYPE_UNKNOWN records. We'll ignore this for the time being ...  */
				if (TRACE_REC_TYPE_UNKNOWN != typed_rec->rec_type) {
					/* syslog(LOG_USER|LOG_ERR, "Expected typed record and got instead %u, termination=%u, at pos %ld with chunk_records=%u",
							typed_rec->rec_type, typed_rec->termination, typed_rec - end + n_records, chunk_records); */
					errno = EPROTO;
					return - __LINE__;
				}
				continue;
			}

			if (typed_rec->generation > generation) {
				/* This record got overrun before we copied it from the shared-memory buffer */
				if (fix_errors) {
					typed_rec->rec_type = TRACE_REC_TYPE_UNKNOWN;
				}
				records_invalidated++;
				/* Also invalidate subsequent records until we find one that is marked as first, or records we have already invalidated. */
				for (struct trace_record *invalid_rec = typed_rec + 1;
					(invalid_rec < end) && !(invalid_rec->termination & TRACE_TERMINATION_FIRST) && (TRACE_REC_TYPE_UNKNOWN != invalid_rec->rec_type);
					invalid_rec++) {
					if (fix_errors) {
						invalid_rec->rec_type = TRACE_REC_TYPE_UNKNOWN;
					}
					records_invalidated++;
				}
			}
			else {
				generation = typed_rec->generation;
			}
		}
	}

	return records_invalidated;

}

int trace_dump_validator(struct trace_record *records, int n_records, bool_t fix_errors, void *context __attribute__((unused)))
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
		if (TRACE_REC_TYPE_BUFFER_CHUNK != records->rec_type) { /* Not well-formed dump data */
			/* syslog(LOG_USER|LOG_ERR, "Expected chunk record and got instead %u at pos %ld",
					records->rec_type, records - end + n_records);*/
			errno = EPROTO;
			return - __LINE__;
		}

		unsigned chunk_records = MIN(records->u.buffer_chunk.records, end - records - 1);
		if (chunk_records < 1) {
			/* syslog(LOG_USER|LOG_ERR, "Invalid chunk header with no subsequent data at pos %ld", records - end + n_records);  */
			errno = EPROTO;
			return - __LINE__;
		}

		// call here

		int rc = trace_typed_record_sequence_validator(records + 1, chunk_records, fix_errors, context);
		if (rc < 0) {
			return rc;
		}

		records_invalidated += rc;

		/* Add the count of invalidates records to the previously computed lost record count */
		if (fix_errors) {
			records->u.buffer_chunk.lost_records += rc;
		}

		records += (chunk_records + 1);
	}

	return records_invalidated;
}
