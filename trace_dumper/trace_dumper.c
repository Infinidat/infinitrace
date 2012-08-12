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
#include <syslog.h>
#include <time.h>
#include "../trace_lib.h"
#include "../trace_user.h"
#include "trace_dumper.h"
#include "filesystem.h"
#include "writer.h"
#include "buffers.h"
#include "init.h"
#include "open_close.h"
#include "metadata.h"

#define TRACE_SEV_X(v, str) [v] = #str,
static const char *sev_to_str[] = {
	TRACE_SEVERITY_DEF
};
#undef TRACE_SEV_X

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
            strncat(severity_str, sev_to_str[i], severity_str_size - 1 - strlen(severity_str));
            first_element = 0;
        }
    }
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

#define STATS_DUMP_DELTA (TRACE_SECOND * 3)
static void possibly_dump_online_statistics(struct trace_dumper_configuration_s *conf)
{
    unsigned long long current_time = trace_get_nsec();
    if (! (conf->dump_online_statistics && current_time > conf->next_stats_dump_ts)) {
        return;
    }

    printf("%s %s", CLEAR_SCREEN, GOTO_TOP);
    dump_online_statistics(conf);

    conf->next_stats_dump_ts = current_time + STATS_DUMP_DELTA;
}


void calculate_delta(const struct trace_mapped_records *mapped_records, unsigned int *delta, unsigned int *delta_a, unsigned int *delta_b, unsigned int *lost_records)
{
    unsigned int last_written_record;
    
    last_written_record = mapped_records->mutab->current_record & mapped_records->imutab->max_records_mask;
    const struct trace_record *last_record = &mapped_records->records[last_written_record];

    if (last_written_record == mapped_records->current_read_record) {
        *lost_records = 0;
        *delta = 0;
        return;
    }    
        
    /* Calculate delta with wraparound considered */
    if (last_written_record > mapped_records->current_read_record) {
        *delta_a = last_written_record - mapped_records->current_read_record;
        *delta_b = 0;
    } else if (last_written_record < mapped_records->current_read_record) {
        *delta_a = mapped_records->imutab->max_records - mapped_records->current_read_record;
        *delta_b = last_written_record;
    }

    
    /* Cap on TRACE_FILE_MAX_RECORDS_PER_CHUNK */
    if (*delta_a + *delta_b > TRACE_FILE_MAX_RECORDS_PER_CHUNK) {
        if (*delta_a > TRACE_FILE_MAX_RECORDS_PER_CHUNK) {
            *delta_a = TRACE_FILE_MAX_RECORDS_PER_CHUNK;
            *delta_b = 0;
        }
        if (*delta_b > TRACE_FILE_MAX_RECORDS_PER_CHUNK - *delta_a) {
            *delta_b = TRACE_FILE_MAX_RECORDS_PER_CHUNK - *delta_a;
        }
    }

    *lost_records = (last_written_record + (last_record->generation * mapped_records->imutab->max_records)) -
        (mapped_records->old_generation * mapped_records->imutab->max_records) + (mapped_records->current_read_record);

    if ((*lost_records) > mapped_records->imutab->max_records && mapped_records->old_generation < last_record->generation) {
        *lost_records -= mapped_records->imutab->max_records;
    } else {
        *lost_records = 0;
    }
        
    *delta = *delta_a + *delta_b;
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
	dump_header_rec->u.dump_header.prev_dump_offset = conf->last_flush_offset;
    dump_header_rec->ts = cur_ts;
}

static void init_buffer_chunk_record(struct trace_dumper_configuration_s *conf, const struct trace_mapped_buffer *mapped_buffer,
                                     struct trace_mapped_records *mapped_records, struct trace_record_buffer_dump **bd,
                                     struct iovec **iovec, unsigned int *iovcnt, unsigned int delta, unsigned int delta_a,
                                     unsigned int lost_records,
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
    (*bd)->lost_records = lost_records;
    (*bd)->records = delta;
    (*bd)->severity_type = mapped_records->imutab->severity_type;
    
    if (lost_records > 0) {
    	time_t seconds = cur_ts / TRACE_SECOND;
    	const char *loss_time = ctime(&seconds);
    	syslog(LOG_USER|LOG_WARNING, "Trace dumper has lost of %u records while writing traces for %s (pid %d) to file %s, resumed writing at process ts=%llu (%s)",
    			lost_records, mapped_buffer->name, mapped_buffer->pid, conf->record_file.filename, cur_ts, loss_time);
    }

    mapped_records->next_flush_offset = conf->record_file.records_written + total_written_records;

    /* Place the buffer chunk header record in the iovec. */
    (*iovec) = &conf->flush_iovec[(*iovcnt)++];
    (*iovec)->iov_base = &mapped_records->buffer_dump_record;
    (*iovec)->iov_len = sizeof(mapped_records->buffer_dump_record);

    /* Add the records in the chunk to the iovec. */
    (*iovec) = &conf->flush_iovec[(*iovcnt)++];
    (*iovec)->iov_base = &mapped_records->records[mapped_records->current_read_record];
    (*iovec)->iov_len = TRACE_RECORD_SIZE * delta_a;
}


static int possibly_write_iovecs_to_disk(struct trace_dumper_configuration_s *conf, unsigned int num_iovecs, unsigned int total_written_records, unsigned long long cur_ts)
{
    int i;
    int rid;
    struct trace_mapped_buffer *mapped_buffer;
    struct trace_mapped_records *mapped_records;
    if (num_iovecs > 1) {
        conf->last_flush_offset = conf->record_file.records_written;
		conf->prev_flush_ts = cur_ts;
		conf->next_flush_ts = cur_ts + conf->ts_flush_delta;

        int ret = trace_dumper_write(conf, &conf->record_file, conf->flush_iovec, num_iovecs, FALSE);
		if ((unsigned int)ret != (total_written_records * sizeof(struct trace_record))) {
			syslog(LOG_ERR|LOG_USER, "Wrote only %d records out of %u requested", (ret / (int)sizeof(struct trace_record)), total_written_records);
            return -1;
		}
        
		for_each_mapped_records(i, rid, mapped_buffer, mapped_records) {
			mapped_records->mutab->latest_flushed_ts = mapped_records->next_flush_ts;
			mapped_records->current_read_record = mapped_records->next_flush_record;
			mapped_records->last_flush_offset = mapped_records->next_flush_offset;
		}
	}

    return 0;
}

static int reap_empty_dead_buffers(struct trace_dumper_configuration_s *conf)
{
    struct trace_mapped_buffer *mapped_buffer;
    struct trace_mapped_records *mapped_records;
    unsigned int lost_records = 0;
    int i, rid;
    unsigned long long total_deltas[0x100];
    unsigned int delta, delta_a, delta_b;
    memset(total_deltas, 0, sizeof(total_deltas));

    for_each_mapped_records(i, rid, mapped_buffer, mapped_records) {
        if (i > (int) ARRAY_LENGTH(total_deltas)) {
            continue;
        }

        if (!mapped_buffer->dead) {
            continue;
        }

        calculate_delta(mapped_records, &delta, &delta_a, &delta_b, &lost_records);
        total_deltas[i] += delta;
        INFO("total deltas", total_deltas[i], rid + 1, i, TRACE_BUFFER_NUM_RECORDS);
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

static int trace_flush_buffers(struct trace_dumper_configuration_s *conf)
{
    struct trace_mapped_buffer *mapped_buffer;
    struct trace_mapped_records *mapped_records;
    unsigned long long cur_ts;
    struct trace_record dump_header_rec;
    struct iovec *iovec;
    unsigned int num_iovecs = 0;
    int i = 0, rid = 0;
    unsigned int total_written_records = 0;
    unsigned int delta, delta_a, delta_b;
    unsigned int lost_records = 0;

	cur_ts = trace_get_nsec();
    init_dump_header(conf, &dump_header_rec, cur_ts, &iovec, &num_iovecs, &total_written_records);

	for_each_mapped_records(i, rid, mapped_buffer, mapped_records) {
		struct trace_record_buffer_dump *bd;
		struct trace_record *last_rec;
        lost_records = 0;
        int rc = dump_metadata_if_necessary(conf, mapped_buffer);
        if (0 != rc) {
            return rc;
        }
        
        if (get_minimal_severity(mapped_records->imutab->severity_type) <= conf->minimal_allowed_severity) {
            WARN("Not dumping pid", mapped_buffer->pid, "with severity type", mapped_records->imutab->severity_type, "due to overwrite");
            continue;
        }
        
        calculate_delta(mapped_records, &delta, &delta_a, &delta_b, &lost_records);
		if (delta == 0) {
            continue;
        }
        
        unsigned int iovec_base_index = num_iovecs;
        init_buffer_chunk_record(conf, mapped_buffer, mapped_records, &bd, &iovec, &num_iovecs, delta, delta_a, lost_records, cur_ts, total_written_records);
		last_rec = (struct trace_record *) (&mapped_records->records[mapped_records->current_read_record + delta_a - 1]);
		if (delta_b) {
			iovec = &conf->flush_iovec[num_iovecs++];
			iovec->iov_base = &mapped_records->records[0];
			iovec->iov_len = TRACE_RECORD_SIZE * delta_b;
			last_rec = (struct trace_record *) &mapped_records->records[delta_b - 1];
		}

        if (conf->online && record_buffer_matches_online_severity(conf, mapped_records->imutab->severity_type)) {
            rc = dump_iovector_to_parser(conf, &conf->parser, &conf->flush_iovec[iovec_base_index], num_iovecs - iovec_base_index);
            if (0 != rc) {
                syslog(LOG_USER|LOG_WARNING,
                "Trace dumper encountered the following error while parsing and filtering %d records for syslog: %s",
                num_iovecs - iovec_base_index, strerror(errno));
            }
        }
        
		mapped_records->next_flush_ts = last_rec->ts;

		total_written_records += delta + 1;
		mapped_records->next_flush_record = mapped_records->current_read_record + delta;
		mapped_records->next_flush_record &= mapped_records->imutab->max_records_mask;
        mapped_records->old_generation = last_rec->generation;
	}

	dump_header_rec.u.dump_header.total_dump_size = total_written_records - 1;
    dump_header_rec.u.dump_header.first_chunk_offset = conf->record_file.records_written + 1;

	if (cur_ts < conf->next_flush_ts) {
		return 0;
	}

    return possibly_write_iovecs_to_disk(conf, num_iovecs, total_written_records, cur_ts);
}


static void handle_overwrite(struct trace_dumper_configuration_s *conf)
{
    if (!conf->max_records_per_second)  {
        return;
    }
    
    unsigned long long current_time = trace_get_nsec();
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
        if (0 != rc) {
        	syslog(LOG_USER|LOG_ERR, "trace_dumper: Error %s encountered while flushing trace buffers.", strerror(errno));
        	break;
        }

        rc = reap_empty_dead_buffers(conf);
        if (0 != rc) {
        	syslog(LOG_USER|LOG_ERR, "trace_dumper: Error %s encountered while emptying dead buffers.", strerror(errno));
        	break;
        }
        
        usleep(20000);
        handle_overwrite(conf);
        
        if (!conf->attach_to_pid && !conf->stopping) {
            map_new_buffers(conf);
        }
        
        rc = unmap_discarded_buffers(conf);
        if (0 != rc) {
        	syslog(LOG_USER|LOG_ERR, "trace_dumper: Error %s encountered while unmapping discarded buffers.", strerror(errno));
            break;
        }
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
