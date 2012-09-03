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
#include "trace_dumper.h"
#include "writer.h"
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

static int trace_dump_metadata(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, struct trace_mapped_buffer *mapped_buffer)
{
    unsigned int num_records;
    int rc;

    mapped_buffer->metadata.metadata_payload_record.ts = trace_get_nsec();
    rc = write_metadata_header_start(conf, record_file, mapped_buffer);
    if (0 != rc) {
        return -1;
    }

    num_records = mapped_buffer->metadata.size / (TRACE_RECORD_PAYLOAD_SIZE) + ((mapped_buffer->metadata.size % (TRACE_RECORD_PAYLOAD_SIZE)) ? 1 : 0);
    rc = trace_dumper_write(conf, record_file, mapped_buffer->metadata.metadata_iovec, 2 * num_records,
    						record_file_should_be_parsed(conf, record_file));
    if ((unsigned int) rc != num_records * sizeof(struct trace_record)) {
    	return -1;
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

void init_metadata_iovector(struct trace_mapped_metadata *metadata, unsigned short pid)
{
    memset(&metadata->metadata_payload_record, 0, sizeof(metadata->metadata_payload_record));
    metadata->metadata_payload_record.rec_type = TRACE_REC_TYPE_METADATA_PAYLOAD;
    metadata->metadata_payload_record.termination = 0;
    metadata->metadata_payload_record.pid = pid;

    unsigned long remaining_length = metadata->size;
    unsigned int i;
    for (i = 0; i < TRACE_METADATA_IOVEC_SIZE / 2; i++) {
        if (remaining_length <= 0) {
            break;
        }
        metadata->metadata_iovec[i*2].iov_base = &metadata->metadata_payload_record;
        metadata->metadata_iovec[i*2].iov_len = TRACE_RECORD_HEADER_SIZE;
        metadata->metadata_iovec[i*2+1].iov_base = &((char *) metadata->base_address)[i * TRACE_RECORD_PAYLOAD_SIZE];
		metadata->metadata_iovec[i*2+1].iov_len = TRACE_RECORD_PAYLOAD_SIZE;
        remaining_length -= TRACE_RECORD_PAYLOAD_SIZE;
    }
}
