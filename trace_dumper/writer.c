/*
 * writer.c
 *
 *  Created on: Aug 8, 2012
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

#define _GNU_SOURCE
#define _LARGEFILE64_SOURCE

#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include "../trace_user.h"
#include "../min_max.h"
#include "filesystem.h"
#include "writer.h"


int total_iovec_len(const struct iovec *iov, int iovcnt)
{
    int total = 0;
    int i;
    for (i = 0; i < iovcnt; i++) {
        total += iov[i].iov_len;
    }

    return total;
}

struct iovec *increase_iov_if_necessary(struct trace_record_file *record_file, size_t required_size)
{
	if (required_size > record_file->iov_allocated_len) {
		record_file->iov_allocated_len = MAX(required_size, record_file->iov_allocated_len + record_file->iov_allocated_len/2);
		record_file->iov = (struct iovec *)realloc(record_file->iov, sizeof(struct iovec) * record_file->iov_allocated_len);
	}
	return record_file->iov;
}

static int trace_dumper_writev(int fd, const struct iovec *iov, int iovcnt)
{
    int length = total_iovec_len(iov, iovcnt);
    char *buffer = (char *) malloc(length);
    if (NULL == buffer) {
    	return -1;
    }

    size_t to_copy = length;
    char *tmp_buffer = buffer;
    int i;
    for (i = 0; i < iovcnt; ++i)
    {
        size_t copy = MIN(iov[i].iov_len, to_copy);
        tmp_buffer = mempcpy((void *) tmp_buffer, (const void *) iov[i].iov_base, copy);

        to_copy -= copy;
        if (to_copy == 0) {
            break;
        }
    }

    ssize_t bytes_written = write(fd, buffer, length);
    free(buffer);
    return bytes_written;
}

int write_single_record(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, const struct trace_record *rec)
{
	const size_t len = sizeof(*rec);
	const struct iovec iov = {
			(void *)rec,
			len
	};

	int rc = trace_dumper_write(conf, record_file, &iov, 1, record_file_should_be_parsed(conf, record_file));
    if ((int)len != rc) {
    	if (rc >= 0) { /* Partial write */
    		errno = ETIMEDOUT;
    	}
        return -1;
    }
    return 0;
}

int dump_iovector_to_parser(const struct trace_dumper_configuration_s *conf, struct trace_parser *parser, const struct iovec *iov, int iovcnt)
{
    int i;
    int rc;
    unsigned char accumulated_trace_record[sizeof(struct trace_record)];
    unsigned char *tmp_ptr = accumulated_trace_record;
    unsigned char *iovec_base_ptr;
    for (i = 0; i < iovcnt; i++) {
        iovec_base_ptr = iov[i].iov_base;
        while (1) {
            unsigned int remaining_rec = sizeof(struct trace_record) - (tmp_ptr - accumulated_trace_record);
            unsigned int copy_len = MIN(remaining_rec, iov[i].iov_len - (iovec_base_ptr - (unsigned char *) iov[i].iov_base));
            memcpy(tmp_ptr, iovec_base_ptr, copy_len);
            tmp_ptr += copy_len;
            iovec_base_ptr += copy_len;
            if (tmp_ptr - accumulated_trace_record == sizeof(struct trace_record)) {
                char formatted_record[10 * 1024];
                size_t record_len = 0;
                rc = TRACE_PARSER__process_next_from_memory(parser, (struct trace_record *) accumulated_trace_record, formatted_record, sizeof(formatted_record), &record_len);
                switch (rc) {
                case 0:
					tmp_ptr = accumulated_trace_record;
					if (record_len) {
						if (!conf->syslog) {
							puts(formatted_record);
						} else {
							syslog(LOG_DEBUG, "%s", formatted_record);
						}
					}
					break;

                case ENODATA:  /* End of file */
                	return 0;

                default:
                	syslog(LOG_USER|LOG_ERR, "Trace dumper failed to format a message because of the following error: %s", strerror(errno));
                	return rc;
                }
            }

            if ((unsigned char *)iovec_base_ptr - (unsigned char *)iov[i].iov_base == (unsigned int) iov[i].iov_len) {
                break;
            }
        }
    }

    return 0;
}


static int dump_to_parser_if_necessary(struct trace_dumper_configuration_s *conf, const struct iovec *iov, int iovcnt, bool_t dump_to_parser)
{
	if (dump_to_parser && conf->online && iovcnt > 0) {
	        int parser_rc = dump_iovector_to_parser(conf, &conf->parser, iov, iovcnt);
	        if (parser_rc != 0) {
	        	int err = errno;
				syslog(LOG_USER|LOG_ERR, "trace_dumper: Dumping parsed traces failed due to %s", strerror(err));
				ERR("Dumping parsed traces failed with error", strerror(err));
				return -1;
	        }
	    }

	return 0;
}


int trace_dumper_write(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, const struct iovec *iov, int iovcnt, bool_t dump_to_parser)
{
	int expected_bytes = total_iovec_len(iov, iovcnt);
    int rc = 0;
    unsigned retries_due_to_full_fs = 0;
    unsigned retries_due_to_partial_write = 0;
    const useconds_t retry_interval = TRACE_SECOND / 60;
    const useconds_t partial_write_retry_interval = 10000;

    if (record_file->fd < 0) {
    	errno = EBADF;
    	expected_bytes = -1;
    }
    else if (expected_bytes > 0)
    {
        while (TRUE) {
            if (iovcnt >= sysconf(_SC_IOV_MAX)) {
                rc = trace_dumper_writev(record_file->fd, iov, iovcnt);
            } else {
                rc = writev(record_file->fd, iov, iovcnt);
            }

            if (rc < 0) {
            	if (errno == ENOSPC) {
					if (0 == retries_due_to_full_fs)
					{
						syslog(LOG_USER|LOG_WARNING, "Writing traces to %s paused due to a full filesystem", record_file->filename);
					}

					++retries_due_to_full_fs;
					if (0!= handle_full_filesystem(conf, iov, iovcnt)) {
						usleep(retry_interval);
					}
					continue;
            	}
            	else
            	{
            		syslog(LOG_USER|LOG_ERR, "Had unexpected error %s while writing to %s", strerror(errno), record_file->filename);
            		expected_bytes = -1;
            		break;
            	}
            }
            else if (rc != expected_bytes) {
            	int err = errno;

            	ERR("Only wrote", rc, "of", expected_bytes, "bytes, and got error", err, ". rewinding by the number of bytes written");
            	off64_t eof_pos = lseek64(record_file->fd, (off64_t)-rc, SEEK_CUR);
            	if (ftruncate64(record_file->fd, eof_pos) < 0) {
            		return -1;
            	}

            	if (0 == retries_due_to_partial_write % 500) {
            		syslog(LOG_USER|LOG_WARNING, "Writing traces to %s had to be rolled back since only %d of %d bytes were written. retried %u times so far.",
            				record_file->filename, rc, expected_bytes, retries_due_to_partial_write);
            	}
            	++retries_due_to_partial_write;
            	usleep(partial_write_retry_interval);
            	continue;
            }

            if (retries_due_to_full_fs > 0) {
            	syslog(LOG_USER|LOG_NOTICE,
            		  "Writing traces to %s resumed after a pause due a full file-system after %u retries every %.2f seconds",
            		  record_file->filename, retries_due_to_full_fs, retry_interval/1E6);
            	retries_due_to_full_fs = 0;
            }

            if (retries_due_to_partial_write > 0) {
                syslog(LOG_USER|LOG_NOTICE,
				  "Writing traces to %s resumed after a pause due to to a partial write after %u retries every %.1f ms",
				  record_file->filename, retries_due_to_partial_write, partial_write_retry_interval/1000.0);
                retries_due_to_partial_write = 0;
            }

            record_file->records_written += expected_bytes / sizeof(struct trace_record);
            break;
        }

        dump_to_parser_if_necessary(conf, iov, iovcnt, dump_to_parser);
    }

    return expected_bytes;
}

int trace_dumper_write_and_sync(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, const struct iovec *iov, int iovcnt)
{
	if (record_file->fd < 0) {
		errno = EBADF;
		return -1;
	}

	if (iovcnt > 0) {
		int num_warn_bytes = total_iovec_len(iov, iovcnt);
		if (trace_dumper_write(conf, record_file, iov, iovcnt, FALSE) != num_warn_bytes) {
			syslog(LOG_USER|LOG_ERR,
					"Trace dumper encountered the following error while writing to the file %s: %s",
					record_file->filename, strerror(errno));
			return -1;
		}
    }

	return 0;
}
