/*
 * open_close.c
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

#include "../platform.h"
#include "../trace_str_util.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <errno.h>
#include <syslog.h>
#include <assert.h>
#include <alloca.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/mman.h>

#include "../trace_user.h"
#include "../file_naming.h"
#include "filesystem.h"
#include "open_close.h"
#include "writer.h"
#include "buffers.h"

static int trace_write_header(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file)
{
    struct utsname ubuf;
    struct trace_record rec;
    struct trace_record_file_header *file_header = &rec.u.file_header;
    int rc;

    memset(&rec, 0, sizeof(rec));
    memset(&ubuf, 0, sizeof(ubuf));
    uname(&ubuf);

    rec.rec_type = TRACE_REC_TYPE_FILE_HEADER;
	rec.termination = (TRACE_TERMINATION_LAST | TRACE_TERMINATION_FIRST);

	snprintf((char *)file_header->machine_id, sizeof(file_header->machine_id), "%s", ubuf.nodename);
    file_header->format_version = TRACE_FORMAT_VERSION;
    file_header->magic = TRACE_MAGIC_FILE_HEADER;

    file_header->flags = 0;
    if (conf->low_latency_write) {
    	file_header->flags |= TRACE_FILE_HEADER_FLAG_LOW_LATENCY_MODE;
    }

    record_file->post_write_validator = NULL;
    rc = write_single_record(conf, record_file, &rec);
	if (rc < 0) {
		syslog(LOG_USER|LOG_ERR, "Failed to write to a data file %s due to error: %s", record_file->filename, strerror(errno));
		return rc;
    }

	if (conf->log_details) {
		syslog(LOG_USER|LOG_INFO, "Trace dumper starting to write to the file %s", record_file->filename);
	}
	return 0;
}

static const size_t TRACE_FILE_SUFFIX_LEN = sizeof(TRACE_FILE_SUFFIX) - 1;

static int generate_file_name(char *filename, const struct trace_dumper_configuration_s *conf, const char *filename_base)
{
	/* The quota code parses the file names to get their creation time, so we have to preserve the old format it expects. */
	const bool_t human_readable = ! trace_quota_is_enabled(conf);

	return trace_generate_file_name(filename, filename_base, sizeof(conf->record_file.filename), human_readable);
}

bool_t is_perf_logging_file_open(struct trace_record_file *record_file)
{
	if (NULL == record_file->perf_log_file) {
		return FALSE;
	}

	int saved_errno = errno;
	long rc = ftell(record_file->perf_log_file);
	if (-1L == rc) {
		if (EBADF == errno) { /* The file is not open yet */
			errno = saved_errno;
		}
		else {  /* Some other, unexpected error occurred */
			syslog(LOG_USER|LOG_WARNING, "Error trying to check the state of the performance logging file: %s", strerror(errno));
		}
		return FALSE;
	}

	TRACE_ASSERT(rc >= 0L);
	return TRUE;
}

static int open_perf_logging_file(struct trace_record_file *record_file, const char *filename)
{
	record_file->perf_log_file = fopen(filename, "wt");
	if (NULL == record_file->perf_log_file) {
		return -1;
	}

	if (EOF == fputs("\"Filename\", \"ts\", \"num bytes\", \"memcpy duration\", \"validation duration\", \"records pending\"\n", record_file->perf_log_file)) {
		fclose(record_file->perf_log_file);
		return -1;
	}
	return 0;
}

static int trace_open_file(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, const char *filename_spec, bool_t autogen_filenames)
{

    char filename[sizeof(record_file->filename)];

    record_file->records_written = 0;
    record_file->mapping_info = NULL;

    TRACE_ASSERT(NULL != filename_spec);
    if (!autogen_filenames) { /* filename_spec specifies a full filename */
        if ((size_t)(stpncpy(filename, filename_spec, sizeof(filename)) - filename) >= sizeof(filename)) {
        	errno = ENAMETOOLONG;
        	return -1;
        }
    } else { /* filename_spec specifies a directory where files are auto-generated */
    	if (trace_create_dir_if_necessary(filename_spec) < 0) {
    		return -1;
    	}

    	generate_file_name(filename, conf, filename_spec);

    	if ((conf->log_performance_to_file) && !is_perf_logging_file_open(record_file)) {
    		static const char perf_log_suffix[] =  "_perf_log.csv";
    		size_t len = strlen(filename) - TRACE_FILE_SUFFIX_LEN;
    		char *perf_log_filename = alloca(len + sizeof(perf_log_suffix));
    		memcpy(perf_log_filename, filename, len);
    		strcpy(perf_log_filename + len, perf_log_suffix);
    		if (0 != open_perf_logging_file(record_file, perf_log_filename)) {
    			syslog(LOG_USER|LOG_ERR, "Failed writing to the performance logging file due to %s", strerror(errno));
    		}
    	}
    }

    INFO("Opening trace file:", filename);
    TRACE_ASSERT(is_closed(record_file));

    int mode = conf->low_latency_write ? O_RDWR : O_WRONLY;
    record_file->fd = TEMP_FAILURE_RETRY(open(filename, mode | O_CREAT | O_TRUNC, 0644));
    if (record_file->fd < 0) {
    	syslog(LOG_ERR|LOG_USER, "Failed to open new trace file %s due to error %s", filename, strerror(errno));
        return -1;
    }

    trace_strncpy_and_terminate(record_file->filename, filename, sizeof(record_file->filename));
    return trace_write_header(conf, record_file);
}

bool_t trace_quota_is_enabled(const struct trace_dumper_configuration_s *conf)
{
	/* The user hasn't disabled trace dumper's quota management */
	return conf->max_records_per_logdir < LLONG_MAX;
}

static bool_t file_should_be_closed(const struct trace_dumper_configuration_s *conf, const struct trace_record_file *record_file)
{
	return (record_file->records_written >= conf->max_records_per_file) || ! trace_dumper_record_file_state_is_ok(record_file);
}

int rotate_trace_file_if_necessary(struct trace_dumper_configuration_s *conf)
{
    int rc = 0;
    if (!conf->write_to_file || conf->fixed_output_filename) {
        return 0;
    }

    if (trace_quota_is_enabled(conf)) {
		while (TRUE) {
			if (total_records_in_logdir(conf->logs_base) > conf->max_records_per_logdir) {
				rc = delete_oldest_trace_file(conf);
				if (0 != rc) {
					return -1;
				}
			} else {
				break;
			}
		}
    }

    /* TODO: Close the notification file when its size exceeds the limit. */

    if (file_should_be_closed(conf, &conf->record_file)) {
        rc |= close_record_file(conf);
    }

    if (file_should_be_closed(conf, &conf->notification_file)) {
		rc |= close_notification_file(conf);
	}

    if (0 != rc) {
    	syslog(LOG_USER|LOG_ERR, "Had the following error while closing a trace file: %s", strerror(errno));
    	return -1;
    }

    /* Reopen journal file */
    rc = open_trace_file_if_necessary(conf);
    if (0 != rc) {
        ERR("Unable to open trace file:", strerror(errno));
        return -1;
    }

    return 0;
}

int open_trace_file_if_necessary(struct trace_dumper_configuration_s *conf)
{
	int rc = 0;
	if ((conf->write_to_file) && is_closed(&conf->record_file)) {
		if (conf->fixed_output_filename) {
			rc = trace_open_file(conf, &conf->record_file, conf->fixed_output_filename, FALSE);
		}
		else {
			rc = trace_open_file(conf, &conf->record_file, conf->logs_base, TRUE);
		}

		if (0 != rc) {
			ERR("Unable to open trace file");
			syslog(LOG_USER|LOG_ERR, "Trace dumper failed to open a trace file due to %s", strerror(errno));
			return rc;
		}
    }

   	if (conf->write_notifications_to_file && is_closed(&conf->notification_file)) {
		if (conf->fixed_notification_filename) {
			rc = trace_open_file(conf, &conf->notification_file, conf->fixed_notification_filename, FALSE);
		}
		else {
			TRACE_ASSERT(NULL != conf->logs_base);
			TRACE_ASSERT(NULL != conf->notifications_subdir);
			char *warn_dir = alloca(strlen(conf->logs_base) + strlen(conf->notifications_subdir) + 4);
			sprintf(warn_dir, "%s/%s", conf->logs_base, conf->notifications_subdir);
			rc = trace_open_file(conf, &conf->notification_file, warn_dir, TRUE);
		}

		if (0 != rc) {
			ERR("Unable to open notification file");
			syslog(LOG_USER|LOG_ERR, "Trace dumper failed to open a notification file due to %s", strerror(errno));
		}
	}

    return rc;
}

const char *trace_record_file_basename(const struct trace_record_file *record_file)
{
	const char *last_slash = strrchr(record_file->filename, '/');
	if (NULL != last_slash) {
		return last_slash + 1;
	}

	return record_file->filename;
}

bool_t is_closed(const struct trace_record_file *file) {
	return file->fd < 0;
}

static int close_file(struct trace_record_file *file, bool_t wait_for_flush) {
	int rc = 0;
	if (!is_closed(file)) {
		trace_dumper_update_written_record_count(file);
		if (NULL != file->mapping_info) {
			rc = trace_dumper_flush_mmapping(file, wait_for_flush);
		}
		else {
			rc = close(file->fd);
			INFO("Closed the file", file->filename, TRACE_NAMED_PARAM(fd, file->fd), rc);
		}

		if (0 == rc) {
			file->fd = -1;
		}
	}
	else {
        INFO("Not closing the alreay closed file", file->filename, TRACE_NAMED_PARAM(fd, file->fd));
    }

	if (0 == rc) {
		TRACE_ASSERT(is_closed(file));

		/* Make sure we're not leaking memory mappings */
		TRACE_ASSERT(NULL == file->mapping_info);
	}
	else {
		TRACE_ASSERT(! is_closed(file));
		syslog(LOG_USER|LOG_ERR, "Trace dumper had error %d (%s) while trying to close the file %s",
				errno, strerror(errno), file->filename);
	}

	return rc;
}

int close_record_file(struct trace_dumper_configuration_s *conf)
{

    int rc = close_file(&conf->record_file, conf->stopping || conf->fixed_output_filename);

    if (0 == rc) {

    	conf->last_flush_offset = 0;
    	conf->header_written = FALSE;

		int i;
		struct trace_mapped_buffer *mapped_buffer;
		struct trace_mapped_records *mapped_records;
		int rid;

		for_each_mapped_records(i, rid, mapped_buffer, mapped_records) {
			mapped_records->last_flush_offset = 0;
			mapped_buffer->last_metadata_offset = 0;
			mapped_buffer->metadata_dumped = FALSE;
		}
	}

    return rc;
}

int close_notification_file(struct trace_dumper_configuration_s *conf)
{
	int rc = close_file(&conf->notification_file, conf->stopping);

	if (is_closed(&conf->notification_file)) {
		struct trace_mapped_buffer *mapped_buffer;
		int i;
		for_each_mapped_buffer(i, mapped_buffer) {
			mapped_buffer->notification_metadata_dumped = FALSE;
		}
	}

	return rc;
}

static int close_timing_file_if_necessary(struct trace_record_file *file)
{
	int rc = 0;
	if (NULL != file->perf_log_file) {
		rc = fclose(file->perf_log_file);
		if (0 == rc) {
			file->perf_log_file = NULL;
		}
	}
	return rc;
}

int close_all_files(struct trace_dumper_configuration_s *conf)
{
	request_file_operations(conf, TRACE_REQ_CLOSE_ALL_FILES);
	return apply_requested_file_operations(conf, TRACE_REQ_CLOSE_ALL_FILES);
}

unsigned request_file_operations(struct trace_dumper_configuration_s *conf, unsigned op_flags)
{
	return __sync_fetch_and_or(&conf->request_flags, op_flags);
}

int apply_requested_file_operations(struct trace_dumper_configuration_s *conf, unsigned op_mask)
{
	int rc = 0;
	const unsigned flags = conf->request_flags & op_mask;
	if (0 != flags) {
	    INFO("Performing requested file operations with", TRACE_INT_AS_HEX(flags), "=", TRACE_INT_AS_HEX(op_mask), "|", conf->request_flags);
	}

	if (flags & TRACE_REQ_CLOSE_NOTIFICATION_FILE) {
		rc |= close_notification_file(conf);
	}

	if (flags & TRACE_REQ_CLOSE_RECORD_FILE) {
		rc |= close_record_file(conf);
	}

	if (flags & TRACE_REQ_CLOSE_NOTIFICATION_TIMING_FILE) {
		rc |= close_timing_file_if_necessary(&conf->notification_file);
	}

	if (flags & TRACE_REQ_CLOSE_RECORD_TIMING_FILE) {
		rc |= close_timing_file_if_necessary(&conf->record_file);
	}

	if (flags & TRACE_REQ_DISCARD_ALL_BUFFERS) {
		discard_all_buffers_immediately(conf);
	}

	static const char snapshot_prefix[] = "snapshot.";

	if (flags & TRACE_REQ_RENAME_RECORD_FILE) {
		rc |= prepend_prefix_to_filename(conf->record_file.filename, snapshot_prefix);
	}

	if (flags & TRACE_REQ_RENAME_NOTIFICATION_FILE) {
		rc |= prepend_prefix_to_filename(conf->notification_file.filename, snapshot_prefix);
	}

	unsigned all_flags = __sync_fetch_and_and(&conf->request_flags, ~flags);

	if (0 != rc) {
		syslog( LOG_USER|LOG_ERR,
				"Trace has encountered the following error while trying to execute operations requested asynchronously corresponding to flags=%X, flag_word=%X: %s",
				flags, all_flags, strerror(errno));
	}
	return rc;
}

