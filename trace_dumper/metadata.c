/*
 * metadata.c
 *
 *  Created on: Aug 9, 2012
 *      Original Author: Yotam Rubin
 *      Maintainer:		 Yitzik Casapu, Infinidat
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

#include <syslog.h>
#include <stdlib.h>
#include <errno.h>
#include "../min_max.h"
#include "../trace_defs.h"
#include "../trace_lib.h"
#include "../trace_user.h"
#include "../trace_clock.h"
#include "trace_dumper.h"
#include "writer.h"
#include "open_close.h"
#include "metadata.h"

static void init_metadata_rec(struct trace_record *rec, const struct trace_mapped_buffer *mapped_buffer)
{
	memset(rec, 0, sizeof(*rec));
    rec->pid = mapped_buffer->pid;
    rec->ts = trace_get_nsec();
    rec->u.metadata.metadata_magic = TRACE_MAGIC_METADATA;
}

static int write_metadata_header_start(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, const struct trace_mapped_buffer *mapped_buffer)
{
    struct trace_record rec;
    init_metadata_rec(&rec, mapped_buffer);
    rec.rec_type = TRACE_REC_TYPE_METADATA_HEADER;
    rec.termination = TRACE_TERMINATION_FIRST;
    rec.u.metadata.metadata_size_bytes = mapped_buffer->metadata.size;

    /* Copy dead PIDs to the header, so the parser will know it can deallocate their resources. */
    int num_dead_pids = MIN(PidList__element_count(&conf->dead_pids), (int)ARRAY_LENGTH(rec.u.metadata.dead_pids));
    int i;
    for (i = 0; i < num_dead_pids; i++) {
    	PidList__dequeue(&conf->dead_pids, rec.u.metadata.dead_pids + i);
    }

    return write_single_record(conf, record_file, &rec);
}

static int write_metadata_end(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, const struct trace_mapped_buffer *mapped_buffer)
{
    struct trace_record rec;
    init_metadata_rec(&rec, mapped_buffer);
	rec.rec_type = TRACE_REC_TYPE_METADATA_PAYLOAD;
	rec.termination = TRACE_TERMINATION_LAST;
	return write_single_record(conf, record_file, &rec);
}

static inline size_t num_metadata_trace_records(size_t metadata_size)
{
	return (metadata_size + TRACE_RECORD_PAYLOAD_SIZE - 1) / TRACE_RECORD_PAYLOAD_SIZE;
}

static int trace_dump_metadata(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, struct trace_mapped_buffer *mapped_buffer)
{
    int rc = open_trace_file_if_necessary(conf);
    if (0 != rc) {
        return rc;
    }

    mapped_buffer->metadata.metadata_payload_record.ts = trace_get_nsec();

    /* TODO: write a validator for metadata. */
    record_file->post_write_validator = NULL;

    rc = write_metadata_header_start(conf, record_file, mapped_buffer);
    if (0 != rc) {
        return -1;
    }

    if (mapped_buffer->metadata.metadata_iovec_len > 0) {
		TRACE_ASSERT(NULL != mapped_buffer->metadata.metadata_iovec);
		rc = trace_dumper_write(conf, record_file, mapped_buffer->metadata.metadata_iovec, mapped_buffer->metadata.metadata_iovec_len);
		if ((size_t) rc != (mapped_buffer->metadata.metadata_iovec_len / 2) * sizeof(struct trace_record)) {
			if (0 == errno) {
				errno = EIO;
			}
			return -1;
		}
    }
    else {
    	syslog(LOG_USER|LOG_WARNING, "Trace dumper could not dump metadata for the process %s (pid %u) because it has length 0",
    			mapped_buffer->name, mapped_buffer->pid);
    }

    return write_metadata_end(conf, record_file, mapped_buffer);
}

int dump_metadata_if_necessary(struct trace_dumper_configuration_s *conf, struct trace_mapped_buffer *mapped_buffer)
{
    if (!mapped_buffer->metadata_dumped) {
        mapped_buffer->last_metadata_offset = conf->record_file.records_written;
        int rc = trace_dump_metadata(conf, &conf->record_file, mapped_buffer);
        if (0 != rc) {
        	syslog(LOG_USER|LOG_ERR, "Failed to dump metadata to the file %s due to error: %s", conf->record_file.filename, strerror(errno));
            ERR("Error dumping metadata");
            mapped_buffer->last_metadata_offset = -1;
            return rc;
        }
    }
    mapped_buffer->metadata_dumped = TRUE;

    if (conf->write_notifications_to_file) {
		if (!mapped_buffer->notification_metadata_dumped) {
			int rc = trace_dump_metadata(conf, &conf->notification_file, mapped_buffer);
			if (0 != rc) {
				syslog(LOG_USER|LOG_ERR, "Failed to dump warnings metadata to the file %s due to error: %s", conf->notification_file.filename, strerror(errno));
				ERR("Error dumping metadata");
				return rc;
			}
		}
		mapped_buffer->notification_metadata_dumped = TRUE;
    }

    return 0;
}

bool_t metadata_dumping_needed(const struct trace_dumper_configuration_s *conf, const struct trace_mapped_buffer *mapped_buffer)
{
    return !mapped_buffer->metadata_dumped || (conf->write_notifications_to_file && !mapped_buffer->notification_metadata_dumped);
}

void init_metadata_iovector(struct trace_mapped_metadata *metadata, trace_pid_t pid)
{
    memset(&metadata->metadata_payload_record, 0, sizeof(metadata->metadata_payload_record));
    metadata->metadata_payload_record.rec_type = TRACE_REC_TYPE_METADATA_PAYLOAD;
    metadata->metadata_payload_record.termination = 0;
    metadata->metadata_payload_record.pid = pid;

    size_t remaining_length = metadata->size;
    size_t num_iovec_pairs = num_metadata_trace_records(remaining_length);
    metadata->metadata_iovec_len = 2*num_iovec_pairs;
    metadata->metadata_iovec = malloc((metadata->metadata_iovec_len + 1) * sizeof(struct iovec));

    unsigned int i;
    for (i = 0; i < num_iovec_pairs; i++) {

        metadata->metadata_iovec[i*2].iov_base = &metadata->metadata_payload_record;
        metadata->metadata_iovec[i*2].iov_len = TRACE_RECORD_HEADER_SIZE;
        metadata->metadata_iovec[i*2+1].iov_base = &((char *) metadata->base_address)[i * TRACE_RECORD_PAYLOAD_SIZE];
        size_t len = MIN(TRACE_RECORD_PAYLOAD_SIZE, remaining_length);
        TRACE_ASSERT(len > 0);
		metadata->metadata_iovec[i*2+1].iov_len = len;
        remaining_length -= len;
    }
    TRACE_ASSERT(remaining_length == 0);

    if (metadata->metadata_iovec[metadata->metadata_iovec_len - 1].iov_len < TRACE_RECORD_PAYLOAD_SIZE) {
    	static const char zeros[TRACE_RECORD_PAYLOAD_SIZE] = { '\0' };
    	metadata->metadata_iovec[metadata->metadata_iovec_len].iov_len = TRACE_RECORD_PAYLOAD_SIZE - metadata->metadata_iovec[metadata->metadata_iovec_len - 1].iov_len;
    	metadata->metadata_iovec[metadata->metadata_iovec_len].iov_base = (void *)zeros;
    	metadata->metadata_iovec_len++;
    }
}

void free_metadata(struct trace_mapped_metadata *metadata)
{
	if (NULL != metadata->metadata_iovec) {
		free(metadata->metadata_iovec);
	}

	metadata->metadata_iovec = NULL;
	metadata->metadata_iovec_len = 0;
}
