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

#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#include <syslog.h>
#include <assert.h>
#include <alloca.h>
#include <limits.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/utsname.h>

#include "../trace_user.h"
#include "filesystem.h"
#include "open_close.h"
#include "writer.h"
#include "buffers.h"


unsigned long long trace_get_walltime(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    return (((unsigned long long)tv.tv_sec) * 1000000) + tv.tv_usec;
}

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

    rc = write_single_record(conf, record_file, &rec);
	if (rc < 0) {
		syslog(LOG_USER|LOG_ERR, "Failed to write to a data file %s due to error: %s", record_file->filename, strerror(errno));
		return rc;
    }

	syslog(LOG_USER|LOG_INFO, "Trace dumper starting to write to the file %s", record_file->filename);
	return 0;
}

static void generate_file_name(char *filename, const struct trace_dumper_configuration_s *conf, const char *filename_base)
{
	const size_t name_len = sizeof(conf->record_file.filename);
	unsigned long long now_ms = trace_get_walltime() / 1000;

	if (trace_quota_is_enabled(conf)) {
		/* The quota code parses the file names to get their creation time, so we have to preserve the format. */
		snprintf(filename, name_len, "%s/trace.%llu.dump", filename_base, now_ms);
	}
	else {
		struct tm now_tm;
		time_t now_sec = now_ms / 1000UL;
		gmtime_r(&now_sec, &now_tm);
		int len = snprintf(filename, name_len, "%s/trace.", filename_base);
		len += strftime(filename + len, name_len - len, "%F--%H-%M-%S--", &now_tm);
		snprintf(filename + len, name_len - len, "%llu.dump", (now_ms % 1000) / 10);
	}
}

static int trace_open_file(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, const char *filename_spec, bool_t autogen_filenames)
{

    char filename[sizeof(record_file->filename)];

    record_file->records_written = 0;

    assert(NULL != filename_spec);
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
    }

    INFO("Opening trace file:", filename);
    assert(record_file->fd < 0);
    record_file->fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (record_file->fd < 0) {
    	syslog(LOG_ERR|LOG_USER, "Failed to open new trace file %s due to error %s", filename, strerror(errno));
        return -1;
    }

    strncpy(record_file->filename, filename, sizeof(record_file->filename));
    return trace_write_header(conf, record_file);
}

bool_t trace_quota_is_enabled(const struct trace_dumper_configuration_s *conf)
{
	/* The user hasn't disabled trace dumper's quota management */
	return conf->max_records_per_logdir < LLONG_MAX;
}

int rotate_trace_file_if_necessary(struct trace_dumper_configuration_s *conf)
{
    int rc;
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

    if (conf->record_file.records_written < conf->max_records_per_file) {
        return 0;
    }

    close_record_file(conf);

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
	if ((conf->write_to_file) && (conf->record_file.fd < 0)) {
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

   	if (conf->write_notifications_to_file && (conf->notification_file.fd < 0)) {
		if (conf->fixed_notification_filename) {
			rc = trace_open_file(conf, &conf->notification_file, conf->fixed_notification_filename, FALSE);
		}
		else {
			assert(NULL != conf->logs_base);
			assert(NULL != conf->notifications_subdir);
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


void close_record_file(struct trace_dumper_configuration_s *conf)
{
    close(conf->record_file.fd);
    conf->record_file.fd = -1;
    conf->last_flush_offset = 0;

    int i;
    struct trace_mapped_buffer *mapped_buffer;
    struct trace_mapped_records *mapped_records;
    conf->header_written = 0;
    int rid;

    for_each_mapped_records(i, rid, mapped_buffer, mapped_records) {
        mapped_records->last_flush_offset = 0;
        mapped_buffer->last_metadata_offset = 0;
        mapped_buffer->metadata_dumped = FALSE;
    }
}

void close_all_files(struct trace_dumper_configuration_s *conf)
{
	if (conf->notification_file.fd >= 0) {
		close(conf->notification_file.fd);
		conf->notification_file.fd = -1;

		struct trace_mapped_buffer *mapped_buffer;
		struct trace_mapped_records *mapped_records;
		int i;
		int rid;
		for_each_mapped_records(i, rid, mapped_buffer, mapped_records) {
			mapped_buffer->notification_metadata_dumped = FALSE;
		}
	}

	if (conf->record_file.fd >= 0) {
		close_record_file(conf);
	}
}

