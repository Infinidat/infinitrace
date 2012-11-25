/***
Copyright 2012 Yotam Rubin <yotamrubin@gmail.com>
   Sponsored by infinidat (http://infinidat.com)

   Modified and maintained by Yitzik Casapu of Infinidat - 2012

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


#undef _GNU_SOURCE
#define _GNU_SOURCE

#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sysexits.h>
#include "../list_template.h"
#include "../bool.h"
#include "../trace_metadata_util.h"
#include "../trace_parser.h"
#include "../min_max.h"
#include "../array_length.h"
#include "../trace_clock.h"
#include <syslog.h>
#include <time.h>
#include <sys/mman.h>
#include <assert.h>
#include "../trace_lib.h"
#include "../trace_user.h"
#include "../trace_str_util.h"
#include "trace_dumper.h"
#include "filesystem.h"
#include "writer.h"
#include "buffers.h"
#include "init.h"
#include "open_close.h"
#include "metadata.h"

static void severity_type_to_str(unsigned int severity_type, char *severity_str, unsigned int severity_str_size)
{
    int i;
    unsigned int first_element = 1;
    memset(severity_str, 0, severity_str_size);
    for (i = TRACE_SEV__MIN; i <= TRACE_SEV__MAX; i++) {
        if (severity_type & (1 << i)) {
            if (!first_element) {
                strncat(severity_str, ", ", severity_str_size);
            }
            strncat(severity_str, trace_severity_to_str_array[i], severity_str_size - 1 - strlen(severity_str));
            first_element = 0;
        }
    }
}

static trace_ts_t get_nsec_monotonic()
{
	const trace_ts_t now = trace_get_nsec_monotonic();
	if ((trace_ts_t) -1 == now) {
		syslog(LOG_ERR|LOG_USER, "Trace dumper has failed to read system time because of the following error: %s", strerror(errno));
	}

	return now;
}

static void dump_online_statistics(const struct trace_dumper_configuration_s *conf)
{
    char display_bar[60];
    char severity_type_str[100];
    unsigned int current_display_index = 0;
    unsigned int next_display_record = 0;
    unsigned int unflushed_records = 0;
    int i;
    unsigned int j;
    int rid;
    struct trace_mapped_buffer *mapped_buffer;
    const struct trace_mapped_records *mapped_records;
    
    for_each_mapped_records(i, rid, mapped_buffer, mapped_records) {
        current_display_index = 0;
        memset(display_bar, '_', sizeof(display_bar));
        display_bar[sizeof(display_bar) - 1] = '\0';
        unflushed_records = 0;
        next_display_record = 0;
        unsigned int display_resolution = mapped_records->imutab->max_records / sizeof(display_bar);
        for (j = 0; j < mapped_records->imutab->max_records; j++) {
            unsigned long long ts = mapped_records->records[j].ts;

            if (j > next_display_record) {
                next_display_record += display_resolution;
                current_display_index++;
            }

            if (!ts) {
                continue;
            }

            if (ts > mapped_records->mutab->latest_flushed_ts) {
                unflushed_records++;
                display_bar[current_display_index] = '#';
            }
        }

        severity_type_to_str(mapped_records->imutab->severity_type, severity_type_str, sizeof(severity_type_str));
        unsigned int usage_percent = unflushed_records / (mapped_records->imutab->max_records / 100);
        char formatted_usage[15];
        if (usage_percent < 50) {
            snprintf(formatted_usage, sizeof(formatted_usage), _F_GREEN("%%%03d"), usage_percent);
        } else if (usage_percent >= 50 && usage_percent < 80) {
            snprintf(formatted_usage, sizeof(formatted_usage), _F_YELLOW_BOLD("%%%03d"), usage_percent);
        } else {
            snprintf(formatted_usage, sizeof(formatted_usage), _F_RED_BOLD("%%%03d"), usage_percent);
        }
        
        printf(_F_MAGENTA("%-16s") _F_GREEN("%-24s") _ANSI_DEFAULTS("[") _F_YELLOW_BOLD("%d") _ANSI_DEFAULTS("]") _ANSI_DEFAULTS("[") _F_BLUE_BOLD("%07x") _ANSI_DEFAULTS("/") _F_BLUE_BOLD("%07x") _ANSI_DEFAULTS("]") "    (%s" _ANSI_DEFAULTS(")") _ANSI_DEFAULTS(" ") "(%s) \n", mapped_buffer->name, severity_type_str, mapped_buffer->pid, unflushed_records, mapped_records->imutab->max_records, formatted_usage, display_bar);
    }
}

static void possibly_dump_online_statistics(struct trace_dumper_configuration_s *conf)
{
    static const unsigned long long STATS_DUMP_DELTA = TRACE_SECOND * 3;

	trace_ts_t current_time = get_nsec_monotonic();
    if (! (conf->dump_online_statistics && current_time > conf->next_stats_dump_ts)) {
        return;
    }

    printf("%s %s", CLEAR_SCREEN, GOTO_TOP);
    dump_online_statistics(conf);

    conf->next_stats_dump_ts = current_time + STATS_DUMP_DELTA;
}

struct records_pending_write {
	unsigned total;
	unsigned up_to_buf_end;
	unsigned from_buf_start;
	unsigned beyond_chunk_size;
	long lost;
	long remaining_before_loss;
};

static trace_record_counter_t adjust_for_overrun(struct trace_mapped_records *mapped_records)
{
	trace_record_counter_t current_record = mapped_records->mutab->current_record;
	assert(current_record >= mapped_records->imutab->max_records - 1);

	trace_record_counter_t additional_skipped;

	for (additional_skipped = 1;	/* TODO: Consider a higher starting value to avoid the new starting point getting overrun. */
		(0 == (mapped_records->records[(current_record + additional_skipped) & mapped_records->imutab->max_records_mask].termination & TRACE_TERMINATION_FIRST));
		additional_skipped++) ;

	mapped_records->current_read_record = current_record + additional_skipped - mapped_records->imutab->max_records;
	return additional_skipped;

	/* TODO: There's a race condition here is that remains to be addressed. Until the records are
	 * actually written to the disk, the writing process will continue to write records. This will result in
	 * some records appearing twice.
	 * A safer solution is required in the longer term */
}

static inline unsigned current_read_index(const struct trace_mapped_records *mapped_records)
{
	return mapped_records->current_read_record & mapped_records->imutab->max_records_mask;
}

static void calculate_delta(
		const struct trace_mapped_records *mapped_records,
		struct records_pending_write *delta)
{

#ifndef _LP64
#warning "Use of this implementation is not recommended on platforms where sizeof(long) < 8, problems with wrap-around are likely."
#endif


	trace_record_counter_t last_written_record = mapped_records->mutab->last_committed_record;
	unsigned last_written_idx = last_written_record & mapped_records->imutab->max_records_mask;
    volatile const struct trace_record *last_record = &mapped_records->records[last_written_idx];

    memset(delta, 0, sizeof(*delta));
    if(TRACE_SEV_INVALID == last_record->severity) {
    	if (-1UL != last_written_record) {  /* Some traces have been written */
    		syslog(LOG_USER|LOG_ERR,
    				"Record %lu was uninitialized but marked as committed while dumping from a buffer with for pid %d",
    				last_written_record, last_record->pid);
    	}
    	delta->remaining_before_loss = mapped_records->imutab->max_records;
    	return;
    }

    /* Verify the record counters haven't wrapped around. On 64-bit platforms this should never happen. */
    assert(last_written_record + 1UL >= mapped_records->current_read_record);
    long backlog_len = last_written_record + 1UL - mapped_records->current_read_record;

    /* Check whether the number of records written to the shared-memory buffers exceeds the number read by the dumper by more than the buffer size.
           * If so - we have lost records. */
    long overrun_records =
    		(long)(backlog_len - mapped_records->imutab->max_records);

    delta->lost = MAX(overrun_records, 0L);
    delta->remaining_before_loss = MAX(-overrun_records, 0L);
    delta->total = MIN(backlog_len, TRACE_FILE_MAX_RECORDS_PER_CHUNK);
    delta->beyond_chunk_size = backlog_len - delta->total;

    unsigned current_read_idx = current_read_index(mapped_records);
    delta->up_to_buf_end  = MIN(delta->total, mapped_records->imutab->max_records - current_read_idx);
    delta->from_buf_start = delta->total - delta->up_to_buf_end;

    assert(delta->total <= TRACE_FILE_MAX_RECORDS_PER_CHUNK);
    assert(delta->from_buf_start + delta->up_to_buf_end == delta->total);
}

static void init_dump_header(struct trace_dumper_configuration_s *conf, struct trace_record *dump_header_rec,
                             unsigned long long cur_ts,
                             struct iovec **iovec, unsigned int *num_iovecs, unsigned int *total_written_records)
{
    memset(dump_header_rec, 0, sizeof(*dump_header_rec));
	*iovec = &conf->flush_iovec[(*num_iovecs)++];
	(*iovec)->iov_base = dump_header_rec;
	(*iovec)->iov_len = sizeof(*dump_header_rec);

    (*total_written_records)++;
    dump_header_rec->rec_type = TRACE_REC_TYPE_DUMP_HEADER;
    dump_header_rec->termination = (TRACE_TERMINATION_LAST | TRACE_TERMINATION_FIRST);
	dump_header_rec->u.dump_header.prev_dump_offset = conf->last_flush_offset;
    dump_header_rec->ts = cur_ts;
    dump_header_rec->u.dump_header.records_previously_discarded = conf->record_file.records_discarded;
}

/* Initialize the buffer chunk header and set-up the iovec for the no wrap-around case. */
static void init_buffer_chunk_record(struct trace_dumper_configuration_s *conf, const struct trace_mapped_buffer *mapped_buffer,
                                     struct trace_mapped_records *mapped_records, struct trace_record_buffer_dump **bd,
                                     struct iovec **iovec, unsigned int *iovcnt,
                                     const struct records_pending_write *deltas,
                                     unsigned long long cur_ts, unsigned int total_written_records)
{
    memset(&mapped_records->buffer_dump_record, 0, sizeof(mapped_records->buffer_dump_record));
    mapped_records->buffer_dump_record.rec_type = TRACE_REC_TYPE_BUFFER_CHUNK;
    mapped_records->buffer_dump_record.ts = cur_ts;
    mapped_records->buffer_dump_record.termination = (TRACE_TERMINATION_LAST |
                                                      TRACE_TERMINATION_FIRST);
    mapped_records->buffer_dump_record.pid = mapped_buffer->pid;

    /* Fill the buffer chunk header */
    (*bd) = &mapped_records->buffer_dump_record.u.buffer_chunk;
    (*bd)->last_metadata_offset = mapped_buffer->last_metadata_offset;
    (*bd)->prev_chunk_offset = mapped_records->last_flush_offset;
    (*bd)->dump_header_offset = conf->last_flush_offset;
    (*bd)->ts = cur_ts;
    (*bd)->lost_records = deltas->lost + mapped_records->num_records_discarded;
    (*bd)->records = deltas->total;
    (*bd)->severity_type = mapped_records->imutab->severity_type;

    mapped_records->next_flush_offset = conf->record_file.records_written + total_written_records;

    /* Place the buffer chunk header record in the iovec. */
    (*iovec) = &conf->flush_iovec[(*iovcnt)++];
    (*iovec)->iov_base = &mapped_records->buffer_dump_record;
    (*iovec)->iov_len = sizeof(mapped_records->buffer_dump_record);

    /* Add the records in the chunk to the iovec. */
    (*iovec) = &conf->flush_iovec[(*iovcnt)++];
    (*iovec)->iov_base = (void *)&mapped_records->records[current_read_index(mapped_records)];
    (*iovec)->iov_len = TRACE_RECORD_SIZE * deltas->up_to_buf_end;
}

static void advance_mapped_record_counters(struct trace_dumper_configuration_s *conf)
{
    int i;
    int rid;
    struct trace_mapped_buffer *mapped_buffer = NULL;
    struct trace_mapped_records *mapped_records = NULL;

	for_each_mapped_records(i, rid, mapped_buffer, mapped_records) {
		mapped_records->mutab->latest_flushed_ts = mapped_records->next_flush_ts;
        mapped_records->current_read_record = mapped_records->next_flush_record;
		mapped_records->last_flush_offset = mapped_records->next_flush_offset;
	}
}

static void reset_discarded_record_counters(struct trace_dumper_configuration_s *conf)
{
    int i;
    int rid;
    struct trace_mapped_buffer *mapped_buffer = NULL;
    struct trace_mapped_records *mapped_records = NULL;

	for_each_mapped_records(i, rid, mapped_buffer, mapped_records) {
		mapped_records->num_records_discarded = 0;
	}

	conf->record_file.records_discarded = 0;
}

static int possibly_write_iovecs_to_disk(struct trace_dumper_configuration_s *conf, unsigned int num_iovecs, unsigned int total_written_records, trace_ts_t cur_ts)
{
    if (num_iovecs > 1) {
    	assert(num_iovecs >= 3);  /* Should have at least dump and chunk headers and some data */
        conf->last_flush_offset = conf->record_file.records_written;
		conf->prev_flush_ts = cur_ts;
		conf->next_flush_ts = cur_ts + conf->ts_flush_delta;

        int ret = trace_dumper_write(conf, &conf->record_file, conf->flush_iovec, num_iovecs, FALSE);
		if ((unsigned int)ret != (total_written_records * sizeof(struct trace_record))) {
			if (ret < 0) {
				if (EAGAIN != errno) {
					syslog(LOG_ERR|LOG_USER, "Had error %s (%d) while writing records", strerror(errno), errno);
				}
				else {
				    int i;
				    int rid;
				    struct trace_mapped_buffer *mapped_buffer = NULL;
				    struct trace_mapped_records *mapped_records = NULL;

					for_each_mapped_records(i, rid, mapped_buffer, mapped_records) {
						assert(mapped_records->current_read_record <= mapped_records->next_flush_record);
						mapped_records->num_records_discarded += (mapped_records->next_flush_record - mapped_records->current_read_record);
					}
				}
			}
			else {
				syslog(LOG_ERR|LOG_USER, "Wrote only %d records out of %u requested", (ret / (int)sizeof(struct trace_record)), total_written_records);
			}
            return -1;
		}
        
		advance_mapped_record_counters(conf);
	}

    return 0;
}

static int reap_empty_dead_buffers(struct trace_dumper_configuration_s *conf)
{
    struct trace_mapped_buffer *mapped_buffer = NULL;
    const struct trace_mapped_records *mapped_records = NULL;
    int i, rid;
    unsigned long long total_deltas[MappedBuffers_NUM_ELEMENTS];
    struct records_pending_write deltas;
    memset(total_deltas, 0, sizeof(total_deltas));

    for_each_mapped_records(i, rid, mapped_buffer, mapped_records) {
        if (!mapped_buffer->dead) {
            continue;
        }

        calculate_delta(mapped_records, &deltas);

        /* Add-up the total number of unwritten records in the buffer */
        total_deltas[i] += deltas.total;
        INFO("total deltas", total_deltas[i], rid + 1, i, TRACE_BUFFER_NUM_RECORDS);

        /* If after adding up all the records this buffer has nothing left to write discard it. */
        if ((rid + 1 == TRACE_BUFFER_NUM_RECORDS) && (total_deltas[i] == 0)) {
            discard_buffer(conf, mapped_buffer);
        }
    }

    return 0;
}


static inline enum trace_severity get_minimal_severity(int severity_type)
{
    unsigned int count = TRACE_SEV__MIN;
    while (!(severity_type & 1)) {
        severity_type >>= 1;
        count++;
    }

    return count;
}


static inline bool_t record_buffer_matches_online_severity(const struct trace_dumper_configuration_s *conf, unsigned int severity_type)
{
    return get_allowed_online_severity_mask(conf) & severity_type;
}

static void possibly_report_record_loss(
		const struct trace_dumper_configuration_s *conf,
		const struct trace_mapped_buffer *mapped_buffer,
		const struct trace_mapped_records *mapped_records,
		const struct records_pending_write *deltas)
{
	unsigned records_pos = mapped_records - mapped_buffer->mapped_records;

	assert(records_pos < TRACE_BUFFER_NUM_RECORDS);
	assert(deltas->lost >= 0);
	assert(deltas->remaining_before_loss >= 0);

	if (deltas->lost > 0) {
		syslog(LOG_USER|LOG_WARNING, "Trace dumper has lost %ld records while writing traces from area %u of %s (pid %d) to file %s.",
				deltas->lost, records_pos, mapped_buffer->name, mapped_buffer->pid, conf->record_file.filename);
	}
	else {
		const double remaining_percent_threshold = 5.0;
		double remaining_percent = deltas->remaining_before_loss * 100.0 / mapped_records->imutab->max_records;
		if (remaining_percent < remaining_percent_threshold) {
			syslog(LOG_USER|LOG_WARNING,
					"Trace dumper's remaining space in buffer area %u for %s (pid %d) has dropped to %.1f%% while writing to to file %s.",
					records_pos, mapped_buffer->name, mapped_buffer->pid, remaining_percent, conf->record_file.filename);
		}
	}
}

static unsigned add_warn_records_to_iov(
		const struct trace_mapped_records *mapped_records,
		unsigned count,
		enum trace_severity threshold_severity,
		struct trace_record_file *record_file)
{
	unsigned iov_idx = 0;
	unsigned recs_covered = 0;
	unsigned start_idx = mapped_records->imutab->max_records_mask & mapped_records->current_read_record;
	unsigned i;

	for (i = 0; i < count; i+= recs_covered) {
		volatile const struct trace_record *rec = (const struct trace_record *)&mapped_records->records[(start_idx + i) & mapped_records->imutab->max_records_mask];
		struct iovec *iov = increase_iov_if_necessary(record_file, iov_idx + 2);

		if ((rec->termination & TRACE_TERMINATION_FIRST) &&
			(TRACE_REC_TYPE_TYPED == rec->rec_type) &&
			(rec->severity >= threshold_severity)) {
				volatile const struct trace_record *const starting_rec = rec;
				do {
					/* In case of wrap-around within the record sequence for a single trace, start a new iovec */
					if (__builtin_expect(rec >= mapped_records->records + mapped_records->imutab->max_records, 0)) {
						assert(rec == mapped_records->records + mapped_records->imutab->max_records);
						recs_covered = mapped_records->imutab->max_records - (start_idx + i);
						assert(recs_covered > 0);
						iov[iov_idx].iov_len = sizeof(*rec) * recs_covered;
						i+= recs_covered;
						iov_idx++;
						rec = mapped_records->records;
						iov[iov_idx].iov_base = (void *)rec;
					}
				} while (0 == ((rec++)->termination & TRACE_TERMINATION_LAST));

				recs_covered = rec - starting_rec;
				if (((rec - 1)->ts != starting_rec->ts) || ((rec - 1)->tid != starting_rec->tid)) {
					syslog(LOG_USER|LOG_NOTICE, "Was about to add a partial record of severity %s to the notification iov, at start_idx=%u, i=%u, recs_covered=%u, count=%u",
							trace_severity_to_str_array[starting_rec->severity], start_idx, i, recs_covered, count);

					/* TODO: If this condition is encountered we should wait briefly for the writing thread to finish writing.
					Apparently this will mainly happen with extra long traces, not common in practice. */
					continue;
				}

				if (i + recs_covered > count) {
					syslog(LOG_USER|LOG_NOTICE, "Record scanning for notifications went beyond the specified count, at start_idx=%u, i=%u, recs_covered=%u, count=%u",
												start_idx, i, recs_covered, count);
					break;
				}

				iov[iov_idx].iov_base = (void *)starting_rec;
				iov[iov_idx].iov_len = sizeof(*rec) * recs_covered;
				iov_idx++;
		}
		else {
			recs_covered = 1;
		}
	}

	return iov_idx;
}


/* Iterate over all the mapped buffers and flush them. The result will be a new dump added to the file, with the
 * records flushed from every buffer that has data pending constituting a chunk.
 * A negative return value indicates an error. A non-negative return value indicates the total number of records still pending
 * writing after the buffer flush */
static int trace_flush_buffers(struct trace_dumper_configuration_s *conf)
{
    struct trace_mapped_buffer *mapped_buffer = NULL;
    struct trace_mapped_records *mapped_records = NULL;
    trace_ts_t cur_ts;
    struct trace_record dump_header_rec;
    struct iovec *iovec;
    unsigned int num_iovecs = 0;
    int i = 0, rid = 0;
    unsigned int total_written_records = 0;
    int total_unflushed_records = 0;
    long lost_records = 0L;
    int notification_records_invalidated = 0;
    int rc = 0;
    trace_record_counter_t min_remaining = TRACE_RECORD_BUFFER_RECS;

	cur_ts = get_nsec_monotonic();

	bool_t premature_call = (cur_ts < conf->next_flush_ts);
	if (!premature_call) {
		init_dump_header(conf, &dump_header_rec, cur_ts, &iovec, &num_iovecs, &total_written_records);
	}
	else {
		syslog(LOG_USER|LOG_DEBUG, "Trace buffer flush called prematurely at %llu < %llu", cur_ts, conf->next_flush_ts);
	}

	for_each_mapped_records(i, rid, mapped_buffer, mapped_records) {
		struct trace_record_buffer_dump *bd = NULL;
		const struct trace_record *last_rec = NULL;
		struct records_pending_write deltas;

        lost_records = 0;
        rc = dump_metadata_if_necessary(conf, mapped_buffer);
        if (0 != rc) {
            return rc;
        }
        
        if (get_minimal_severity(mapped_records->imutab->severity_type) <= conf->minimal_allowed_severity) {
            WARN("Not dumping pid", mapped_buffer->pid, "with severity type", mapped_records->imutab->severity_type, "due to overwrite");
            continue;
        }
        
        calculate_delta(mapped_records, &deltas);
        total_unflushed_records += deltas.beyond_chunk_size;
        if (premature_call) {
        	total_unflushed_records += deltas.total;
        	continue;
        }

        lost_records = deltas.lost;
        if (lost_records) {
        	lost_records += adjust_for_overrun(mapped_records);
        	calculate_delta(mapped_records, &deltas);
        	deltas.lost += lost_records;
        }
        else if (0 == deltas.total) {
            continue;
        }
        
        unsigned int iovec_base_index = num_iovecs;
        init_buffer_chunk_record(
        		conf, mapped_buffer, mapped_records,
        		&bd, &iovec, &num_iovecs,
        		&deltas, cur_ts, total_written_records);

		if (deltas.from_buf_start) {
			iovec = &conf->flush_iovec[num_iovecs++];
			iovec->iov_base = (void *)&mapped_records->records[0];
			iovec->iov_len = TRACE_RECORD_SIZE * deltas.from_buf_start;
			last_rec = (const struct trace_record *) &mapped_records->records[deltas.from_buf_start - 1];
		}
		else {
			last_rec = (const struct trace_record *) (&mapped_records->records[
			                    (mapped_records->imutab->max_records_mask & mapped_records->current_read_record) + deltas.up_to_buf_end - 1]);
		}


		assert(	(TRACE_TERMINATION_LAST & last_rec->termination) ||
				/* Make sure this is not due to record buffer overflow overwriting *last_rec */
				(mapped_records->mutab->current_record - mapped_records->current_read_record >= deltas.total));


		/* Note: there's a possible race condition here that could lead to silent record loss
		 * if *last_rec gets overwritten by incoming data before we retrieve the ts from it. */
		mapped_records->next_flush_ts     = last_rec->ts;
		mapped_records->next_flush_record = mapped_records->current_read_record + deltas.total;

        possibly_report_record_loss(conf, mapped_buffer, mapped_records, &deltas);
        min_remaining = MIN(min_remaining, (trace_record_counter_t)(deltas.remaining_before_loss));

        if (conf->write_notifications_to_file && (mapped_records->imutab->severity_type >= (1U << conf->minimal_notification_severity))) {
        	/* TODO: Implement a more clever validator that takes level thresholds into account. */
    		conf->notification_file.post_write_validator = trace_typed_record_sequence_validator;
    		conf->notification_file.validator_context = NULL;

			unsigned int num_warn_iovecs = add_warn_records_to_iov(mapped_records, deltas.total, conf->minimal_notification_severity, &conf->notification_file);
			trace_dumper_write_to_record_file(conf, &conf->notification_file, num_warn_iovecs);
			if (conf->notification_file.validator_last_result < 0) {
				syslog( LOG_USER|LOG_WARNING,
						"Trace dumper's data validation found an unrecoverable error with code %d while writing notifications to the file %s",
						conf->notification_file.validator_last_result, conf->notification_file.filename);
			}
			else {
				notification_records_invalidated += conf->notification_file.validator_last_result;
			}
        }

        if (conf->online && record_buffer_matches_online_severity(conf, mapped_records->imutab->severity_type)) {
            rc = dump_iovector_to_parser(conf, &conf->parser, &conf->flush_iovec[iovec_base_index], num_iovecs - iovec_base_index);
            if (0 != rc) {
                syslog(LOG_USER|LOG_WARNING,
					"Trace dumper encountered the following error while parsing and filtering %lu records bound for %s to %s: %s",
					total_iovec_len(&conf->flush_iovec[iovec_base_index], num_iovecs - iovec_base_index) / sizeof(struct trace_record),
					conf->record_file.filename,
					conf->syslog ? "syslog" : "standard output",
					strerror(errno));
            }
        }
        
		total_written_records += deltas.total + 1;
	}

	if (!premature_call) {
		dump_header_rec.u.dump_header.total_dump_size = total_written_records - 1;
		trace_dumper_update_written_record_count(&conf->notification_file);
		trace_dumper_update_written_record_count(&conf->record_file);
		dump_header_rec.u.dump_header.first_chunk_offset = conf->record_file.records_written + 1;

		conf->record_file.post_write_validator = trace_dump_validator;
		conf->record_file.validator_context = NULL;
		rc = possibly_write_iovecs_to_disk(conf, num_iovecs, total_written_records, cur_ts);
		if (rc < 0) {
			if (EAGAIN == errno) {
				advance_mapped_record_counters(conf);
				rc = total_unflushed_records;	/* We had to discard records, but we consider them to be successfully written in this context. */
			}
			return rc;
		}

		if ((conf->record_file.validator_last_result > 0) || (notification_records_invalidated > 0)) {
			syslog( LOG_USER|LOG_WARNING,
					"Trace dumper has had to invalidate %d record(s) from trace record file %s, and %d record(s) from the notification file %s, which had been overrun while writing."
					" remaining records: %lu",
					conf->record_file.validator_last_result, conf->record_file.filename,
					notification_records_invalidated, conf->notification_file.filename,
					min_remaining);
			conf->record_file.validator_last_result = 0;
			notification_records_invalidated = 0;
		}

		/* The latest chunk written has successfully output information about any discarded records, so reset the counters. */
		reset_discarded_record_counters(conf);
	}
    return total_unflushed_records;
}


static void handle_overwrite(struct trace_dumper_configuration_s *conf)
{
    if (!conf->max_records_per_second)  {
        return;
    }
    
    unsigned long long current_time = get_nsec_monotonic();
    DEBUG("Checking overrwrite. Wrote", conf->record_file.records_written - conf->last_overwrite_test_record_count,
          "records in a second. Minimal severity is now", conf->minimal_allowed_severity);
    if (current_time - conf->last_overwrite_test_time < TRACE_SECOND) {
        return;
    }
    
    if (conf->record_file.records_written - conf->last_overwrite_test_record_count > conf->max_records_per_second) {
        conf->minimal_allowed_severity = MIN(conf->minimal_allowed_severity + 1, TRACE_SEV__MAX);
        conf->next_possible_overwrite_relaxation = current_time + RELAXATION_BACKOFF;
        WARN("Overrwrite occurred. Wrote", conf->record_file.records_written - conf->last_overwrite_test_record_count,
             "records in a second. Minimal severity is now", conf->minimal_allowed_severity);
    } else {
        if (conf->minimal_allowed_severity && (current_time > conf->next_possible_overwrite_relaxation)) {
            conf->minimal_allowed_severity = MAX(conf->minimal_allowed_severity - 1, 0);
            INFO("Relaxing overwrite filter. Write", conf->record_file.records_written - conf->last_overwrite_test_record_count,
                 "records in a second. Minimal severity is now", conf->minimal_allowed_severity);
        }
    }

    conf->last_overwrite_test_time = current_time;
    conf->last_overwrite_test_record_count = conf->record_file.records_written;
}

/* Periodic housekeeping functions: Look for any processes that have started and need to have their traces collected, or that have ended, allowing any resouces
 * allocating for serving them to be freed.
 * Return value:
 * 0 		- If housekeeping was performed successfully
 * EAGAIN 	- If the function was called prematurely and no housekeeping was done
 * < 0		- If an error occurred.
 *  */
static int do_housekeeping_if_necessary(struct trace_dumper_configuration_s *conf)
{
	static const trace_ts_t HOUSEKEEPING_INTERVAL = 10000000; /* 10ms */
	const trace_ts_t now = get_nsec_monotonic();


	if (now < conf->next_housekeeping_ts) {
		return EAGAIN;
	}
	conf->next_housekeeping_ts = now + HOUSEKEEPING_INTERVAL;

	int rc = reap_empty_dead_buffers(conf);
    if (0 != rc) {
    	syslog(LOG_USER|LOG_ERR, "trace_dumper: Error %s encountered while emptying dead buffers.", strerror(errno));
    	return rc;
    }

    handle_overwrite(conf);
    apply_requested_file_operations(conf, TRACE_REQ_ALL_OPS);

    if (!conf->attach_to_pid && !conf->stopping) {
        rc = map_new_buffers(conf);
        if (0 != rc) {
        	syslog(LOG_USER|LOG_ERR, "trace_dumper: Error %s encountered while mapping new buffers.", strerror(errno));
        	return rc;
        }
    }

    rc = unmap_discarded_buffers(conf);
    if (0 != rc) {
    	syslog(LOG_USER|LOG_ERR, "trace_dumper: Error %s encountered while unmapping discarded buffers.", strerror(errno));
    }

    return rc;
}

static int dump_records(struct trace_dumper_configuration_s *conf)
{
    int rc;
    bool_t file_creation_err = FALSE;
    while (1) {
        rc = rotate_trace_file_if_necessary(conf);
        if (0 != rc) {
        	syslog(LOG_USER|LOG_ERR, "trace_dumper: Error %s encountered while rotating trace files.", strerror(errno));
        	file_creation_err = TRUE;
            break;
        }

        if ((conf->stopping || conf->attach_to_pid) && !has_mapped_buffers(conf)) {
            return 0;
        }
        
        rc = open_trace_file_if_necessary(conf);
        if (rc != 0) {
        	syslog(LOG_USER|LOG_ERR, "trace_dumper: Error %s encountered while opening the trace file.", strerror(errno));
        	file_creation_err = TRUE;
        	break;
        }
        
        possibly_dump_online_statistics(conf);
        
        rc = trace_flush_buffers(conf);
        if (rc > TRACE_FILE_IMMEDIATE_FLUSH_THRESHOLD) {
        	struct timespec ts = { 0, conf->ts_flush_delta };
        	nanosleep(&ts, NULL);
        	continue;
        }
        else if (rc < 0) {
        	syslog(LOG_USER|LOG_ERR, "trace_dumper: Error %s encountered while flushing trace buffers.", strerror(errno));
        	break;
        }

        rc = do_housekeeping_if_necessary(conf);
        if (EAGAIN == rc) { /* No housekeeping performed */
			usleep(1000);
		}
        else if (rc < 0) {
        	break;
        }
        else assert(0 == rc);
    }

    rc = errno;
    syslog(LOG_USER|LOG_ERR, "trace_dumper: Error encountered while writing traces: %s.", strerror(rc));
    ERR("Unexpected failure writing trace file:", strerror(rc));
    switch (rc) {
    case ENOMEM:
    	return EX_SOFTWARE;

    case ENAMETOOLONG:
    	return EX_USAGE;

    default:
    	break;
    }

    if (file_creation_err) {
    	return EX_CANTCREAT;
    }

    return EX_IOERR;
}


static int op_dump_records(struct trace_dumper_configuration_s *conf)
{
    int rc;

    rc = attach_and_map_buffers(conf);
    if (0 != rc) {
        return EX_NOINPUT;
    }

    conf->start_time = trace_get_walltime();
    return dump_records(conf);
}

static int op_dump_stats(struct trace_dumper_configuration_s *conf)
{
    int rc;

    rc = attach_and_map_buffers(conf);
	if (0 != rc) {
		return EX_NOINPUT;
	}

    dump_online_statistics(conf);
    return 0;
}

static int run_dumper(struct trace_dumper_configuration_s *conf)
{
    switch (conf->op_type) {
    case OPERATION_TYPE_DUMP_RECORDS:
        return op_dump_records(conf);
        break;
    case OPERATION_TYPE_DUMP_BUFFER_STATS:
        return op_dump_stats(conf);
        break;
    default:
        break;
    }

    return 0;
}


int main(int argc, char **argv)
{
    struct trace_dumper_configuration_s *conf = trace_dumper_get_configuration();
    memset(conf, 0, sizeof(*conf));
    
    if (0 != parse_commandline(conf, argc, argv)) {
    	print_usage(argv[0]);
        return EX_USAGE;
    }

    if (!conf->write_to_file && !conf->online && !conf->dump_online_statistics) {
            fprintf(stderr, "%s: Must specify either -w, -o or -v\n", argv[0]);
            print_usage(argv[0]);
            return EX_USAGE;
    }

    int rc = init_dumper(conf);
    if (0 != rc) {
    	if (EX_USAGE == rc) {
    		print_usage(argv[0]);
    	}
    	else {
    		fprintf(stderr, "%s failed to start with error code %d (see sysexits.h for its meaning)\n", argv[0], rc);
    	}
        return rc;
    }
    
    if (0 != set_signal_handling()) {
    	fprintf(stderr, "Error encountered while trying to set signal handlers: %s\n", strerror(errno));
    	return EX_OSERR;
    }

    rc = run_dumper(conf);
    if ((0 != rc) && (conf->online)) {
    	fprintf(stderr,
    		"Error encountered while writing traces: %s, please see the syslog for more details.\nExiting with error code %d (see sysexits.h for its meaning)\n",
    		strerror(errno), rc);
    }
    return rc;
}
