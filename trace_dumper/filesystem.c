#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <sys/statvfs.h>
#include <syslog.h>
#include <string.h>
#include <limits.h>

#include "../trace_defs.h"
#include "../bool.h"
#include "../trace_lib.h"
#include "../trace_user.h"
#include "../file_naming.h"
#include "../trace_str_util.h"
#include "trace_dumper.h"
#include "writer.h"
#include "filesystem.h"


long long get_file_size(const char *filename)
{
    struct stat st;
    int rc = stat(filename, &st);
    
    if (0 != rc) {
        return -1;
    } else {
        return st.st_size;
    }
}

static long long free_bytes_in_fs(const char *mnt)
{
    struct statvfs vfs;
    int rc = statvfs(mnt, &vfs);
    if (0 != rc) {
        return -1;
    }

    return vfs.f_bsize * vfs.f_bfree;
}

static int get_trace_file_timestamp(const char *filename)
{
    if (!trace_is_valid_file_name(filename)) {
        return -1;
    }

    char timestamp[50];
    trace_strncpy_and_terminate(timestamp, filename + strlen(TRACE_FILE_PREFIX), sizeof(timestamp));
    char *tmp_ptr = index(timestamp, '.');
    if (NULL == tmp_ptr) {
        return -1;
    }

    *tmp_ptr = '\0';
    long int result = strtol(timestamp, (char **) NULL, 10);
    if (result == LONG_MAX || result == LONG_MIN) {
        return -1;
    }

    return result;
}

static int find_oldest_trace_file(const struct trace_dumper_configuration_s *conf, char *filename, unsigned int filename_size)
{
    DIR *dir;
    struct dirent *ent;
    int min_timestamp = INT_MAX;
    int tmp_timestamp = 0;
    char tmp_filename[0x100];
    dir = opendir(conf->logs_base);

    if (dir == NULL) {
    	syslog(LOG_USER|LOG_WARNING, "Failed to open the trace directory %s", conf->logs_base);
    	return -1;
    }

    while (TRUE) {
        ent = readdir(dir);
        if (NULL == ent) {
            goto Exit;
        }

        tmp_timestamp = get_trace_file_timestamp(ent->d_name);
        if (tmp_timestamp < 0) {
            continue;
        }
        if (min_timestamp > tmp_timestamp) {
            min_timestamp = tmp_timestamp;
            snprintf(tmp_filename, sizeof(tmp_filename), "%s/%s", conf->logs_base, ent->d_name);
        }
    }

Exit:
    trace_strncpy_and_terminate(filename, tmp_filename, filename_size);
    closedir(dir);
    return 0;
}

int delete_oldest_trace_file(const struct trace_dumper_configuration_s *conf)
{
    char filename[0x100] = { '\0' };
    int rc = find_oldest_trace_file(conf, filename, sizeof(filename));
    if (0 != rc) {
    	syslog(LOG_NOTICE|LOG_USER, "Failed to find an oldest trace file to delete");
    	return -1;
    }

    INFO("Deleting oldest trace file", filename);
    rc = unlink(filename);
    if (0 != rc) {
    	syslog(LOG_WARNING|LOG_USER, "Failed to delete the log file %s due to error: %s", filename, strerror(errno));
    }
    return rc;
}


long long total_records_in_logdir(const char *logdir)
{
    DIR *dir;
    struct dirent *ent;
    long long total_bytes = 0;
    dir = opendir(logdir);

    if (dir == NULL) {
    	int err = errno;
    	switch (err) {
    	case ENOENT:  /* The directory hasn't yet been created */
    		syslog(LOG_NOTICE|LOG_USER, "The log-directory %s hasn't yet been created", logdir);
    		return 0;

    	default:
			syslog(LOG_USER|LOG_ERR, "Error %s while trying to open the log directory %s", strerror(err), logdir);
			ERR("Error opening dir %s", strerror(err));
			return -1;
    	}
    }


    while (TRUE) {
        ent = readdir(dir);
        if (NULL == ent) {
            goto Exit;
        }

        if (!trace_is_valid_file_name(ent->d_name)) {
            continue;
        }
        char full_filename[0x100];
        snprintf(full_filename, sizeof(full_filename), "%s/%s", logdir, ent->d_name);
        long long file_size = get_file_size(full_filename);
        if (file_size < 0LL) {
            ERR("The file size of", full_filename, "is smaller than 0 (", file_size, ")");
            closedir(dir);
            return -1;
        }

        total_bytes += file_size;
    }

Exit:
    closedir(dir);
    // If not a multiple of a trace record - return an error
    if (total_bytes % sizeof(struct trace_record)) {
    	syslog(LOG_USER|LOG_WARNING, "At least one file in the directory %s appears to be corrupt, with a size that's not a multiple of %lu", logdir, sizeof(struct trace_record));
        INFO(total_bytes, "is not a multiple of", sizeof(struct trace_record));
        return 0;
    }

    return total_bytes / sizeof(struct trace_record);
}

unsigned long long calculate_free_percentage(unsigned int percent, const char *logdir)
{
    if (percent > 100 || percent == 0) {
        return 0;
    }

    long long records_in_logdir = total_records_in_logdir(logdir);
    if (-1 == records_in_logdir) {
        records_in_logdir = 0;
    }

    long long free_bytes = free_bytes_in_fs(logdir) + (records_in_logdir * sizeof(struct trace_record));
    return (free_bytes / 100) * percent;

}

int handle_full_filesystem(const struct trace_dumper_configuration_s *conf, const struct iovec *iov, unsigned int num_iovecs)
{
    long long total_iov_length = total_iovec_len(iov, num_iovecs);
    long long free_bytes_remaining = free_bytes_in_fs(conf->logs_base);

    /* Note: In the unit test environment we might have several dumpers running, and they could delete each other's files.
     * Not sure how to handle this.
     *  if (conf->attach_to_pid) {
        return 0;
    } */

    if (free_bytes_remaining < 0) {
        return -1;
    }

    while (total_iov_length > free_bytes_remaining) {
        if (!conf->fixed_output_filename) {
            if (0 != delete_oldest_trace_file(conf)) {
            	return -1;
            }
        } else {
            ERR("Request to write", total_iov_length, "while there are", free_bytes_remaining, "on the filesystem. Aborting");
            return -1;
        }

        free_bytes_remaining = free_bytes_in_fs(conf->logs_base);
		if (free_bytes_remaining < 0) {
			return -1;
		}
    }

    if (total_iov_length > free_bytes_remaining) {
        return -1;
    }

    return 0;
}


int trace_create_dir_if_necessary(const char *base_dir)
{
	int saved_errno = errno;
	int rc = mkdir(base_dir, 0755);
	if (rc < 0)
	{
		switch (errno)
		{
		case EEXIST:
			errno = saved_errno;
			break;

		default:
			syslog(LOG_ERR|LOG_USER, "The trace directory %s does not exist and could not be created due to error %s",
					base_dir, strerror(errno));
			return -1;
		}
	}

	return 0; /* Created successfully */
}

int prepend_prefix_to_filename(const char *filename, const char *prefix)
{
    char dir[0x100];
    char base[0x100];
    char orig_filename[0x100];
    char snapshot_filename[sizeof(dir) + sizeof(base) + 0x10];

    trace_strncpy_and_terminate(orig_filename, filename, sizeof(orig_filename));
    char *dirname_ptr = dirname(orig_filename);
    trace_strncpy_and_terminate(dir, dirname_ptr, sizeof(dir));
    trace_strncpy_and_terminate(orig_filename, filename, sizeof(orig_filename));
    char *basename_ptr = basename(orig_filename);
    trace_strncpy_and_terminate(base, basename_ptr, sizeof(base));
    snprintf(snapshot_filename, sizeof(snapshot_filename), "%s/%s%s", dir, prefix, base);
    return rename(filename, snapshot_filename);
}

