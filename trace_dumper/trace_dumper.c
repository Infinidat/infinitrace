#undef _GNU_SOURCE
#define _GNU_SOURCE
#include <getopt.h>
#include <signal.h>
#include <libgen.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sysexits.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include "../list_template.h"
#include "filesystem.h"
#include "../bool.h"
#include "../trace_metadata_util.h"
#include "../trace_parser.h"
#include "../min_max.h"
#include "../array_length.h"
#include <syslog.h>
#include <time.h>
#include <sys/sysinfo.h>
#include "../trace_lib.h"
#include "../trace_user.h"

#define COLOR_BOOL conf->color
#include "../colors.h"
#define MAX_FILTER_SIZE (10)
#define METADATA_IOVEC_SIZE 2*(MAX_METADATA_SIZE/TRACE_RECORD_PAYLOAD_SIZE+1)
#define MAX_FILTER_SIZE (10)
#define METADATA_IOVEC_SIZE 2*(MAX_METADATA_SIZE/TRACE_RECORD_PAYLOAD_SIZE+1)

// The threshold stands at about 60 MBps
#define OVERWRITE_THRESHOLD_PER_SECOND (1000000)
#define TRACE_SECOND (1000000000ULL)
#define RELAXATION_BACKOFF (TRACE_SECOND * 10)

struct trace_mapped_metadata {
    struct iovec metadata_iovec[METADATA_IOVEC_SIZE];
    struct trace_record metadata_payload_record;
    unsigned long log_descriptor_count;
    unsigned long type_definition_count;
    unsigned int size;
    void *base_address;
    struct trace_log_descriptor *descriptors;
};
    
struct trace_mapped_records {
    struct trace_record *records;
    struct trace_records_mutable_metadata *mutab;
    struct trace_records_immutable_metadata *imutab;
    
    unsigned long long current_read_record;
    unsigned int last_flush_offset;

    unsigned long long next_flush_ts;
    unsigned int next_flush_record;
    unsigned int next_flush_offset;
	unsigned int old_generation;

    struct trace_record buffer_dump_record;
};

#define TRACE_BUFNAME_LEN (0x100)
#define MAX_BUFFER_COUNT (10)

struct trace_mapped_buffer {
    char name[TRACE_BUFNAME_LEN];
    void *records_buffer_base_address;
    unsigned long records_buffer_size;
    unsigned long last_metadata_offset;
    bool_t metadata_dumped;
    struct trace_mapped_records mapped_records[TRACE_BUFFER_NUM_RECORDS];
    struct trace_mapped_metadata metadata;
    unsigned short pid;
    unsigned int dead;
    unsigned long long process_time;
};

CREATE_LIST_PROTOTYPE(MappedBuffers, struct trace_mapped_buffer);
CREATE_LIST_IMPLEMENTATION(MappedBuffers, struct trace_mapped_buffer);

typedef char buffer_name_t[0x100];
CREATE_LIST_PROTOTYPE(BufferFilter, buffer_name_t);
CREATE_LIST_IMPLEMENTATION(BufferFilter, buffer_name_t);

#define TRACE_FILE_PREFIX "trace."

#define TRACE_METADATA_IOVEC_SIZE  (2*(MAX_METADATA_SIZE/TRACE_RECORD_PAYLOAD_SIZE+1))

#define TRACE_PREFERRED_FILE_MAX_RECORDS_PER_FILE        0x1000000
#define PREFERRED_NUMBER_OF_TRACE_HISTORY_FILES (7)
#define TRACE_PREFERRED_MAX_RECORDS_PER_LOGDIR        (TRACE_PREFERRED_FILE_MAX_RECORDS_PER_FILE) * PREFERRED_NUMBER_OF_TRACE_HISTORY_FILES;
#define TRACE_FILE_MAX_RECORDS_PER_CHUNK       0x10000

struct trace_record_file {
    unsigned long records_written;
    char filename[0x100];
    int fd;
};

enum operation_type {
    OPERATION_TYPE_DUMP_RECORDS,
    OPERATION_TYPE_DUMP_BUFFER_STATS,
};

struct trace_dumper_configuration_s {
    const char *logs_base;
    const char *attach_to_pid;
    int should_quit;
    struct trace_record_matcher_spec_s severity_filter[SEVERITY_FILTER_LEN];
    unsigned int header_written;
    unsigned int write_to_file;
    unsigned int dump_online_statistics;
    const char *fixed_output_filename;
    unsigned int online;
    unsigned int trace_online;
    unsigned int debug_online;
    unsigned int info_online;
    unsigned int warn_online;
    unsigned int error_online;
    unsigned int syslog;
    unsigned long long start_time;
    unsigned int no_color_specified;
    unsigned int color;
    enum trace_severity minimal_allowed_severity;
    unsigned long long next_possible_overwrite_relaxation;
    unsigned long long last_overwrite_test_time;
    unsigned long long last_overwrite_test_record_count;

    const char *quota_specification;
    long long max_records_per_logdir;
    unsigned long long max_records_per_file;
    unsigned long long max_records_per_second;
    int stopping;
	struct trace_record_file record_file;
	unsigned int last_flush_offset;
    enum operation_type op_type;
	unsigned long long prev_flush_ts;
	unsigned long long next_flush_ts;
	unsigned long long ts_flush_delta;
	unsigned long long next_stats_dump_ts;
    struct trace_parser parser;
    BufferFilter filtered_buffers;
    MappedBuffers mapped_buffers;
    struct iovec flush_iovec[1 + (3 * MAX_BUFFER_COUNT * TRACE_RECORD_BUFFER_RECS)];
};

static struct trace_dumper_configuration_s trace_dumper_configuration;

#define SHM_DIR "/dev/shm"

bool_t is_trace_shm_region(const char *shm_name)
{
    if (strncmp(shm_name, TRACE_SHM_ID, strlen(TRACE_SHM_ID)) == 0) {
        return TRUE;
    } else {
        return FALSE;
    }
}

pid_t get_pid_from_shm_name(const char *shm_name)
{
    char str_pid[10];
    shm_name += strlen(TRACE_SHM_ID);
    char *underscore = strstr(shm_name, "_");
    
    if (NULL == underscore) {
        return -1;
    }

    if ((unsigned long) (underscore - shm_name) >= sizeof(str_pid)) {
        return -1;
    }
    
    memcpy(str_pid, shm_name, underscore - shm_name);
    str_pid[underscore - shm_name] = '\0';
    return atoi(str_pid);
    
}

bool_t is_static_log_data_shm_region(const char *shm_name)
{
    if (strstr(shm_name, "static_trace_metadata") != NULL) {
        return TRUE;
    } else {
        return FALSE;
    }
}

bool_t is_dynamic_log_data_shm_region(const char *shm_name)
{
    if (strstr(shm_name, "dynamic_trace_data") != 0) {
        return TRUE;
    } else {
        return FALSE;
    }
}

static int dump_iovector_to_parser(struct trace_dumper_configuration_s *conf, struct trace_parser *parser, const struct iovec *iov, int iovcnt)
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
                unsigned int was_record_formatted = 0;
                rc = TRACE_PARSER__process_next_from_memory(parser, (struct trace_record *) accumulated_trace_record, formatted_record, sizeof(formatted_record), &was_record_formatted);
                tmp_ptr = accumulated_trace_record;
                if (was_record_formatted) {
                    if (!conf->syslog) {
                        printf("%s\n", formatted_record);
                    } else {
                        syslog(LOG_DEBUG, "%s", formatted_record);
                    }
                }
                if (0 != rc) {
                	REPORT_AND_RETURN(-1);
                }
            }

            if ((unsigned char *)iovec_base_ptr - (unsigned char *)iov[i].iov_base == (unsigned int) iov[i].iov_len) {
                break;
            }
        }
    }
    
    return 0;
}

static int total_iovec_len(const struct iovec *iov, int iovcnt)
{
    int total = 0;
    int i;
    for (i = 0; i < iovcnt; i++) {
        total += iov[i].iov_len;
    }

    return total;
}

static int trace_dumper_writev(int fd, const struct iovec *iov, int iovcnt)
{
    int length = total_iovec_len(iov, iovcnt);
    char *buffer = (char *) malloc(length);
    size_t to_copy = length;
    char *tmp_buffer = buffer;
    int i;
    for (i = 0; i < iovcnt; ++i)
    {
        size_t copy = MIN(iov[i].iov_len, to_copy);
        tmp_buffer = mempcpy((void *) tmp_buffer, (void *) iov[i].iov_base, copy);

        to_copy -= copy;
        if (to_copy == 0) {
            break;
        }
    }

    ssize_t bytes_written = write(fd, buffer, length);
    free(buffer);
    return bytes_written;
}

bool_t is_trace_file(const char *filename)
{
    if (strncmp(filename, TRACE_FILE_PREFIX, strlen(TRACE_FILE_PREFIX)) != 0) {
          return FALSE;
    } else {
        return TRUE;
    }
}

int get_trace_file_timestamp(const char *filename)
{
    if (!is_trace_file(filename)) {
        return -1;
    }
    
    char timestamp[50];
    strncpy(timestamp, filename + strlen(TRACE_FILE_PREFIX), sizeof(timestamp));
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

static int find_oldest_trace_file(struct trace_dumper_configuration_s *conf, char *filename, unsigned int filename_size)
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
    strncpy(filename, tmp_filename, filename_size);
    closedir(dir);
    return 0;
}

static int delete_oldest_trace_file(struct trace_dumper_configuration_s *conf)
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


#define for_each_mapped_records(_i_, _rid_, _mapped_buffer_, _mr_)      \
    for (({_i_ = 0; MappedBuffers__get_element_ptr(&conf->mapped_buffers, i, &_mapped_buffer_);}); _i_ < MappedBuffers__element_count(&conf->mapped_buffers); ({_i_++; MappedBuffers__get_element_ptr(&conf->mapped_buffers, i, &_mapped_buffer_);})) \
        for (({_rid_ = 0; _mr_ = &_mapped_buffer_->mapped_records[_rid_];}); _rid_ < TRACE_BUFFER_NUM_RECORDS; ({_rid_++; _mr_ = &_mapped_buffer_->mapped_records[_rid_];}))

#define for_each_mapped_buffer(_i_, _mapped_buffer_)      \
    for (({_i_ = 0; MappedBuffers__get_element_ptr(&conf->mapped_buffers, i, &_mapped_buffer_);}); _i_ < MappedBuffers__element_count(&conf->mapped_buffers); ({_i_++; MappedBuffers__get_element_ptr(&conf->mapped_buffers, i, &_mapped_buffer_);}))

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
            strncat(severity_str, sev_to_str[i], severity_str_size);
            first_element = 0;
        }
    }
}

static void dump_online_statistics(struct trace_dumper_configuration_s *conf)
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
    struct trace_mapped_records *mapped_records;
    
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

static int handle_full_filesystem(struct trace_dumper_configuration_s *conf, const struct iovec *iov, unsigned int num_iovecs)
{
    long long total_iov_length = total_iovec_len(iov, num_iovecs);
    long long free_bytes_remaining = free_bytes_in_fs(conf->logs_base);
    
    if (conf->attach_to_pid) {
        return 0;
    }
    if (free_bytes_remaining < 0) {
        return -1;
    }

    if (total_iov_length > free_bytes_remaining) {
        if (!conf->fixed_output_filename) {
            delete_oldest_trace_file(conf);
        } else {
            ERR("Request to write", total_iov_length, "while there are", free_bytes_remaining, "on the filesystem. Aborting");
            return -1;
        }
    }

    free_bytes_remaining = free_bytes_in_fs(conf->logs_base);
    if (free_bytes_remaining < 0) {
        return -1;
    }

    if (total_iov_length > free_bytes_remaining) {
        return -1;
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

static int trace_dumper_write(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, const struct iovec *iov, int iovcnt, bool_t dump_to_parser)
{
	int expected_bytes = total_iovec_len(iov, iovcnt);
    int rc = 0;
    unsigned retries_due_to_full_fs = 0;
    unsigned retries_due_to_partial_write = 0;
    const useconds_t retry_interval = TRACE_SECOND / 60;
    const useconds_t partial_write_retry_interval = 10000;
    
    if (conf->record_file.fd >= 0) {
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
						syslog(LOG_USER|LOG_WARNING, "Writing traces to %s paused due to a full filesystem", conf->record_file.filename);
					}
					handle_full_filesystem(conf, iov, iovcnt);
					++retries_due_to_full_fs;
            	}
            	else
            	{
            		syslog(LOG_USER|LOG_ERR, "Had unexpected error %s while writing to %s", strerror(errno), conf->record_file.filename);
            	}
                usleep(retry_interval);
                continue;
            }
            else if (rc != expected_bytes) {
            	int err = errno;

            	ERR("Only wrote", rc, "of", expected_bytes, "bytes, and got error", err, ". rewinding by the number of bytes written");
            	off64_t eof_pos = lseek64(record_file->fd, (off64_t)-rc, SEEK_CUR);
            	ftruncate64(record_file->fd, eof_pos);

            	if (0 == retries_due_to_partial_write % 500) {
            		syslog(LOG_USER|LOG_WARNING, "Writing traces to %s had to be rolled back since only %d of %d bytes were written. retried %u times so far.",
            				conf->record_file.filename, rc, expected_bytes, retries_due_to_partial_write);
            	}
            	++retries_due_to_partial_write;
            	usleep(partial_write_retry_interval);
            	continue;
            }

            if (retries_due_to_full_fs > 0) {
            	syslog(LOG_USER|LOG_NOTICE,
            		  "Writing traces to %s resumed after a pause due a full file-system after %u retries every %.2f seconds",
            		  conf->record_file.filename, retries_due_to_full_fs, retry_interval/1E6);
            	retries_due_to_full_fs = 0;
            }

            if (retries_due_to_partial_write > 0) {
                syslog(LOG_USER|LOG_NOTICE,
				  "Writing traces to %s resumed after a pause due to to partial write after %u retries every %.1f ms",
				  conf->record_file.filename, retries_due_to_partial_write, partial_write_retry_interval/1000.0);
                retries_due_to_partial_write = 0;
            }

            record_file->records_written += expected_bytes / sizeof(struct trace_record);
            break;
        }
    }

    dump_to_parser_if_necessary(conf, iov, iovcnt, dump_to_parser);

    return expected_bytes;
}

static void init_metadata_iovector(struct trace_mapped_metadata *metadata, unsigned short pid)
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

#define SIMPLE_WRITE(__conf__, __data__, __size__) do {                   \
                                                                        \
        struct iovec __iov__ = {__data__, __size__}; rc = trace_dumper_write(conf, &conf->record_file, &__iov__, 1, TRUE); } while (0);

static int write_metadata_header_start(struct trace_dumper_configuration_s *conf, struct trace_mapped_buffer *mapped_buffer)
{
    struct trace_record rec;
    int rc;
    rec.rec_type = TRACE_REC_TYPE_METADATA_HEADER;
    rec.termination = TRACE_TERMINATION_FIRST;
    rec.pid = mapped_buffer->pid;
    rec.ts = trace_get_nsec();
    rec.u.metadata.metadata_size_bytes = mapped_buffer->metadata.size;
    SIMPLE_WRITE(conf, &rec, sizeof(rec));
    if (rc != sizeof(rec)) {
        return -1;
    }
    
    return 0;
}


static int write_metadata_end(struct trace_dumper_configuration_s *conf, struct trace_mapped_buffer *mapped_buffer)
{
    struct trace_record rec;
    int rc;
	memset(&rec, 0, sizeof(rec));
	rec.rec_type = TRACE_REC_TYPE_METADATA_PAYLOAD;
	rec.termination = TRACE_TERMINATION_LAST;
    rec.pid = mapped_buffer->pid;
    rec.ts = trace_get_nsec();
    SIMPLE_WRITE(conf, &rec, sizeof(rec));
    if (rc != sizeof(rec)) {
        return -1;
    }

    return 0;
}

static int trace_dump_metadata(struct trace_dumper_configuration_s *conf, struct trace_mapped_buffer *mapped_buffer)
{
    struct trace_record rec;
    unsigned int num_records;
    int rc;

    mapped_buffer->metadata.metadata_payload_record.ts = trace_get_nsec();

    memset(&rec, 0, sizeof(rec));
    rc = write_metadata_header_start(conf, mapped_buffer);
    if (0 != rc) {
        return -1;
    }
    
    num_records = mapped_buffer->metadata.size / (TRACE_RECORD_PAYLOAD_SIZE) + ((mapped_buffer->metadata.size % (TRACE_RECORD_PAYLOAD_SIZE)) ? 1 : 0);
    rc = trace_dumper_write(conf, &conf->record_file, mapped_buffer->metadata.metadata_iovec, 2 * num_records, TRUE);
    if ((unsigned int) rc != num_records * sizeof(struct trace_record)) {
    	return -1;
    }

    return write_metadata_end(conf, mapped_buffer);
}

static int stat_pid(unsigned short pid, struct stat *stat_buf)
{
    char filename[0x100];
    snprintf(filename, sizeof(filename), "/proc/%d", pid);
    return stat(filename, stat_buf);
}

static int get_process_time(unsigned short pid, unsigned long long *curtime)
{
    struct stat stat_buf;
    int rc = stat_pid(pid, &stat_buf);
    if (0 != rc) {
    	REPORT_AND_RETURN(-1);
    }

    *curtime = stat_buf.st_ctim.tv_sec * 1000000000ULL;
    *curtime += stat_buf.st_ctim.tv_nsec;
    return 0;
}

static int delete_shm_files(unsigned short pid)
{
    INFO("Deleting shm files for pid", pid);
    char dynamic_trace_filename[0x100];
    char static_log_data_filename[0x100];
    char full_dynamic_trace_filename[0x100];
    char full_static_log_data_filename[0x100];
    int rc;
    snprintf(dynamic_trace_filename, sizeof(dynamic_trace_filename), "_trace_shm_%d_dynamic_trace_data", pid);
    snprintf(static_log_data_filename, sizeof(static_log_data_filename), "_trace_shm_%d_static_trace_metadata", pid);
    snprintf(full_dynamic_trace_filename, sizeof(full_dynamic_trace_filename), "%s/%s", SHM_DIR, dynamic_trace_filename);
    snprintf(full_static_log_data_filename, sizeof(full_static_log_data_filename), "%s/%s", SHM_DIR, static_log_data_filename);

    rc = unlink(full_dynamic_trace_filename);
    rc |= unlink(full_static_log_data_filename);

    return rc;
}

bool_t trace_should_filter(struct trace_dumper_configuration_s *conf __attribute__((unused)), const char *buffer_name)
{
    buffer_name_t filter;
    memset(filter, 0, sizeof(filter));
    strncpy(filter, buffer_name, sizeof(filter));
    int rc = BufferFilter__find_element(&conf->filtered_buffers, &filter);
    if (rc >= 0) {
        return TRUE;
    } else {
        return FALSE;
    }
}

static int map_buffer(struct trace_dumper_configuration_s *conf, pid_t pid)
{
    int static_fd, dynamic_fd;
    char dynamic_trace_filename[0x100];
    char static_log_data_filename[0x100];
    char full_dynamic_trace_filename[0x100];
    char full_static_log_data_filename[0x100];
    int rc;
    snprintf(dynamic_trace_filename, sizeof(dynamic_trace_filename), "_trace_shm_%d_dynamic_trace_data", pid);
    snprintf(static_log_data_filename, sizeof(static_log_data_filename), "_trace_shm_%d_static_trace_metadata", pid);
    snprintf(full_dynamic_trace_filename, sizeof(full_dynamic_trace_filename), "%s/%s", SHM_DIR, dynamic_trace_filename);
    snprintf(full_static_log_data_filename, sizeof(full_static_log_data_filename), "%s/%s", SHM_DIR, static_log_data_filename);

    int trace_region_size = get_file_size(full_dynamic_trace_filename);
    if (trace_region_size <= 0) {
        ERR("Unable to read region size");
        rc = -1;
        goto delete_shm_files;
    }

   int static_log_data_region_size = get_file_size(full_static_log_data_filename);
    if (static_log_data_region_size <= 0) {
        ERR("Unable to read static region size: %s", static_log_data_filename);
        rc = -1;
        goto delete_shm_files;
    }

    dynamic_fd = shm_open(dynamic_trace_filename, O_RDWR, 0);
    if (dynamic_fd < 0) {
        ERR("Unable to open dynamic buffer %s: %s", dynamic_trace_filename, strerror(errno));
        rc = -1;
        goto delete_shm_files;
    }
    
    static_fd = shm_open(static_log_data_filename, O_RDWR, 0);
    if (dynamic_fd < 0) {
        ERR("Unable to open static buffer: %s", strerror(errno));
        rc = -1;
        goto close_static;

    }

    void *mapped_dynamic_addr = mmap(NULL, trace_region_size, PROT_READ | PROT_WRITE, MAP_SHARED, dynamic_fd, 0);
    if (MAP_FAILED == mapped_dynamic_addr) {
        ERR("Unable to map log information buffer");
        rc = -1;
        goto close_dynamic;

    }
    
    void * mapped_static_log_data_addr = mmap(NULL, static_log_data_region_size, PROT_READ | PROT_WRITE, MAP_SHARED, static_fd, 0);

    if (MAP_FAILED == mapped_static_log_data_addr) {
        ERR("Unable to map static log area: %s", strerror(errno));
        rc = -1;
        goto unmap_dynamic;
    }
    
    struct trace_buffer *unmapped_trace_buffer = (struct trace_buffer *) mapped_dynamic_addr;
    struct trace_mapped_buffer *new_mapped_buffer = NULL;
    struct trace_metadata_region *static_log_data_region = (struct trace_metadata_region *) mapped_static_log_data_addr;
    
    if (trace_should_filter(conf, static_log_data_region->name)) {
        rc = 0;
        INFO("Filtering buffer", static_log_data_region->name);
        goto unmap_static;

    }
    
    if (0 != MappedBuffers__allocate_element(&conf->mapped_buffers)) {
        rc = -1;
        goto unmap_static;
        return -1;
    }

    MappedBuffers__get_element_ptr(&conf->mapped_buffers, MappedBuffers__element_count(&conf->mapped_buffers) - 1, &new_mapped_buffer);
    memset(new_mapped_buffer, 0, sizeof(*new_mapped_buffer));
    if (static_log_data_region_size > MAX_METADATA_SIZE) {
        ERR("Error, metadata size %x too large", static_log_data_region_size);
        rc = -1;
        goto unmap_static;
    }

    new_mapped_buffer->records_buffer_base_address = mapped_dynamic_addr;
    new_mapped_buffer->records_buffer_size = trace_region_size;
    new_mapped_buffer->metadata.log_descriptor_count = static_log_data_region->log_descriptor_count;
    new_mapped_buffer->metadata.type_definition_count = static_log_data_region->type_definition_count;
    new_mapped_buffer->metadata.descriptors = (struct trace_log_descriptor *) static_log_data_region->data;
    new_mapped_buffer->metadata.size = static_log_data_region_size;
    new_mapped_buffer->metadata.base_address = mapped_static_log_data_addr;
    new_mapped_buffer->pid = (unsigned short) pid;
    new_mapped_buffer->metadata_dumped = FALSE;
    unsigned long long process_time;
    rc = get_process_time(pid, &process_time);
    if (0 != rc) {
        rc = 0;
        WARN("Process", pid, "no longer exists");
        process_time = 0;
    }

    new_mapped_buffer->process_time = process_time;
    relocate_metadata(static_log_data_region->base_address, mapped_static_log_data_addr, (char *) new_mapped_buffer->metadata.descriptors,
                      new_mapped_buffer->metadata.log_descriptor_count, new_mapped_buffer->metadata.type_definition_count);
    static_log_data_region->base_address = mapped_static_log_data_addr;
    init_metadata_iovector(&new_mapped_buffer->metadata, new_mapped_buffer->pid);
    strncpy(new_mapped_buffer->name, static_log_data_region->name, sizeof(new_mapped_buffer->name));
    unsigned int i;
    for (i = 0; i < TRACE_BUFFER_NUM_RECORDS; i++) {
        struct trace_mapped_records *mapped_records;

        mapped_records = &new_mapped_buffer->mapped_records[i];
        mapped_records->records = unmapped_trace_buffer->u._all_records[i].records;
        mapped_records->mutab = &unmapped_trace_buffer->u._all_records[i].mutab;
        mapped_records->imutab = &unmapped_trace_buffer->u._all_records[i].imutab;
        mapped_records->last_flush_offset = 0;
        mapped_records->current_read_record = 0;
    }

    INFO("new process joined" ,"pid =", new_mapped_buffer->pid, "name =", new_mapped_buffer->name);
    rc = 0;
    goto exit;
    MappedBuffers__remove_element(&conf->mapped_buffers, MappedBuffers__element_count(&conf->mapped_buffers) - 1);
unmap_static:
    munmap(mapped_static_log_data_addr, static_log_data_region_size);
unmap_dynamic:
    munmap(mapped_dynamic_addr, trace_region_size);
close_dynamic:
    close(dynamic_fd);
close_static:
    close(static_fd);
delete_shm_files:
    delete_shm_files(pid);
exit:
	if (0 != rc) {
		const char *err_name = strerror(errno);
		const char *proc_name = ((NULL == new_mapped_buffer) ? "(unknown)" : new_mapped_buffer->name);
		syslog(LOG_USER|LOG_ERR, "Failed to map buffer for pid %d - %s. Last Error: %s.", (int) pid, proc_name, err_name);
	}
	return rc;
}

static bool_t buffer_mapped(struct trace_dumper_configuration_s * conf, unsigned short pid)
{
    int i;
    for (i = 0; i < MappedBuffers__element_count(&conf->mapped_buffers); i++) {
        struct trace_mapped_buffer *mapped_buffer;
        MappedBuffers__get_element_ptr(&conf->mapped_buffers, i, &mapped_buffer);
        if (mapped_buffer->pid == pid) {
            return TRUE;
        }
    }

    return FALSE;
}

static int process_potential_trace_buffer(struct trace_dumper_configuration_s *conf, const char *shm_name)
{
    int rc = 0;
    if (!is_trace_shm_region(shm_name) && !is_static_log_data_shm_region(shm_name)) {
        return 0;
    }

    pid_t pid = get_pid_from_shm_name(shm_name);
    if (pid <= 0) {
    	return -1;
    }

    if (is_dynamic_log_data_shm_region(shm_name) && !buffer_mapped(conf, pid)) {
        rc = map_buffer(conf, pid);
    }


    return rc;
}

static int map_new_buffers(struct trace_dumper_configuration_s *conf)
{
    DIR *dir;
    struct dirent *ent;
    int rc = 0;
    dir = opendir(SHM_DIR);

    if (dir == NULL) {
    	syslog(LOG_USER|LOG_ERR, "Failed to access the shared-memory directory " SHM_DIR);
    	return -1;
    }
    
    while (TRUE) {
        ent = readdir(dir);
        if (NULL == ent) {
            goto exit;
        }

        rc = process_potential_trace_buffer(conf, ent->d_name);
        if (0 != rc) {
        	syslog(LOG_USER|LOG_ERR, "Failed to process the trace buffer %s.", ent->d_name);
            ERR("Error processing trace buffer", ent->d_name);
            continue;
        }
    }
exit:
    closedir(dir);
    return 0;
}

static bool_t process_exists(unsigned short pid) {
    struct stat buf;
    char filename[0x100];
    snprintf(filename, sizeof(filename), "/proc/%d", pid);
    int rc = stat(filename, &buf);
    if (0 == rc) {
        return TRUE;
    } else {
        return FALSE;
    }
}

static long long total_records_in_logdir(const char *logdir)
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
        
        if (!is_trace_file(ent->d_name)) {
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



static void discard_buffer(struct trace_dumper_configuration_s *conf, struct trace_mapped_buffer *mapped_buffer)
{
    INFO("Discarding pid", mapped_buffer->pid, mapped_buffer->name);
    int rc = munmap(mapped_buffer->metadata.base_address, mapped_buffer->metadata.size);
    if (0 != rc) {
        ERR("Error unmapping metadata for buffer", mapped_buffer->name);
        return;
    }

    rc = munmap(mapped_buffer->records_buffer_base_address, mapped_buffer->records_buffer_size);
    if (0 != rc) {
        ERR("Error unmapping records for buffer", mapped_buffer->name);
        return;
    }

    delete_shm_files(mapped_buffer->pid);
    struct trace_mapped_buffer *tmp_mapped_buffer;
    int i;
    for_each_mapped_buffer(i, tmp_mapped_buffer) {
        if (mapped_buffer == tmp_mapped_buffer) {
            MappedBuffers__remove_element(&conf->mapped_buffers, i);
        }
    }
}

static int unmap_discarded_buffers(struct trace_dumper_configuration_s *conf)
{
    int i;
    struct trace_mapped_buffer *mapped_buffer;
    for_each_mapped_buffer(i, mapped_buffer) {
        if (!process_exists(mapped_buffer->pid)) {
            mapped_buffer->dead = 1;
        }
    }

    return 0;
}

static unsigned long long trace_get_walltime(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    return (((unsigned long long)tv.tv_sec) * 100000) + tv.tv_usec;
}

static int trace_write_header(struct trace_dumper_configuration_s *conf)
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
	SIMPLE_WRITE(conf, &rec, sizeof(rec));
	if (rc != sizeof(rec)) {
		REPORT_AND_RETURN(-1);
    }

	return 0;
}


static int trace_create_dir_if_necessary(const char *base_dir)
{
	int rc = mkdir(base_dir, 0755);
	if (rc < 0)
	{
		switch (errno)
		{
		case EEXIST:
			break;

		default:
			syslog(LOG_ERR|LOG_USER, "The trace directory %s does not exist and could not be created due to error %s",
					base_dir, strerror(errno));
			return -1;
		}
	}

	return 0; /* Created successfully */
}


static int trace_open_file(struct trace_dumper_configuration_s *conf, struct trace_record_file *record_file, const char *filename_base)
{
    unsigned long long now;
    char filename[0x100];
    int rc;

    record_file->records_written = 0;
    now = trace_get_walltime() / 1000;

    if (conf->fixed_output_filename) {
        strncpy(filename, conf->fixed_output_filename, sizeof(filename));
    } else {
    	if (trace_create_dir_if_necessary(filename_base) < 0) {
    		return -1;
    	}
        snprintf(filename, sizeof(filename),
                 "%s/trace.%lld.dump", filename_base, now);
    }

    INFO("Opening trace file:", filename);
    record_file->fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (record_file->fd < 0) {
    	syslog(LOG_ERR|LOG_USER, "Failed to open new trace file %s due to error %s", filename, strerror(errno));
        fprintf(stderr, "Error opening %s for writing\n", filename);
        return -1;
    }

    rc = trace_write_header(conf);
    strncpy(record_file->filename, filename, sizeof(record_file->filename));
    REPORT_AND_RETURN(rc);
}

void calculate_delta(struct trace_mapped_records *mapped_records, unsigned int *delta, unsigned int *delta_a, unsigned int *delta_b, unsigned int *lost_records)
{
    unsigned int last_written_record;
    
    last_written_record = mapped_records->mutab->current_record & mapped_records->imutab->max_records_mask;
    struct trace_record *last_record = &mapped_records->records[last_written_record];

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

static int dump_metadata_if_necessary(struct trace_dumper_configuration_s *conf, struct trace_mapped_buffer *mapped_buffer)
{
    if (!mapped_buffer->metadata_dumped) {
        mapped_buffer->last_metadata_offset = conf->record_file.records_written;
        int rc = trace_dump_metadata(conf, mapped_buffer);
        if (0 != rc) {
            ERR("Error dumping metadata");
            mapped_buffer->last_metadata_offset = -1;
            REPORT_AND_RETURN(-1);
        }
    }
    
    mapped_buffer->metadata_dumped = TRUE;
    return 0;
}

static void init_buffer_chunk_record(struct trace_dumper_configuration_s *conf, struct trace_mapped_buffer *mapped_buffer,
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
    (*bd) = &mapped_records->buffer_dump_record.u.buffer_chunk;
    (*bd)->last_metadata_offset = mapped_buffer->last_metadata_offset;
    (*bd)->prev_chunk_offset = mapped_records->last_flush_offset;
    (*bd)->dump_header_offset = conf->last_flush_offset;
    (*bd)->ts = cur_ts;
    (*bd)->lost_records = lost_records;
    (*bd)->records = delta;
    (*bd)->severity_type = mapped_records->imutab->severity_type;
    
    mapped_records->next_flush_offset = conf->record_file.records_written + total_written_records;
    (*iovec) = &conf->flush_iovec[(*iovcnt)++];
    (*iovec)->iov_base = &mapped_records->buffer_dump_record;
    (*iovec)->iov_len = sizeof(mapped_records->buffer_dump_record);

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

static enum trace_severity get_minimal_severity(int severity_type)
{
    unsigned int count = 1;
    while (!(severity_type & 1)) {
        severity_type >>= 1;
        count++;
    }

    return count;
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
            if (conf->attach_to_pid) {
                return -1;
            }
        }
    }


    return 0;
}

unsigned int get_allowed_online_severity_mask(struct trace_dumper_configuration_s *conf)
{
    return ((conf->trace_online << TRACE_SEV_FUNC_TRACE) | (conf->debug_online << TRACE_SEV_DEBUG) | (conf->info_online << TRACE_SEV_INFO) |
                                  (conf->warn_online << TRACE_SEV_WARN) | (conf->error_online << TRACE_SEV_ERR) | (conf->error_online << TRACE_SEV_FATAL));
}

static bool_t record_buffer_matches_online_severity(struct trace_dumper_configuration_s *conf, unsigned int severity_type)
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
                return -1;
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

static void close_record_file(struct trace_dumper_configuration_s *conf)
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

static int rotate_trace_file_if_necessary(struct trace_dumper_configuration_s *conf)
{
    int rc;
    if (!conf->write_to_file || conf->fixed_output_filename) {
        return 0;
    }
    
#ifdef TRACE_DELETE_OLDEST_FILE
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
#endif

    if (conf->record_file.records_written < conf->max_records_per_file) {
        return 0;
    }

    close_record_file(conf);
    
    /* Reopen journal file */
    rc = trace_open_file(conf, &conf->record_file, conf->logs_base);
    if (0 != rc) {
        ERR("Unable to open trace file:", strerror(errno));
        return -1;
    }

    return 0;
}

static int open_trace_file_if_necessary(struct trace_dumper_configuration_s *conf)
{
    if (conf->write_to_file && conf->record_file.fd < 0) {
        int rc = trace_open_file(conf, &conf->record_file, conf->logs_base);
        if (0 != rc) {
            ERR("Unable to open trace file");
            return -1;
        }
    }

    return 0;
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

static bool_t has_mapped_buffers(struct trace_dumper_configuration_s *conf)
{
    return MappedBuffers__element_count(&conf->mapped_buffers);
}

static int dump_records(struct trace_dumper_configuration_s *conf)
{
    int rc;
    while (1) {
        rc = rotate_trace_file_if_necessary(conf);
        if (0 != rc) {
        	syslog(LOG_USER|LOG_ERR, "trace_dumper: Error %s encountered while rotating trace files.", strerror(errno));
            break;
        }

        if ((conf->stopping || conf->attach_to_pid) && !has_mapped_buffers(conf)) {
            return 0;
        }
        
        rc = open_trace_file_if_necessary(conf);
        if (rc != 0) {
        	syslog(LOG_USER|LOG_ERR, "trace_dumper: Error %s encountered while opening the trace file.", strerror(errno));
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
    return EX_IOERR;
}

static int attach_and_map_buffers(struct trace_dumper_configuration_s *conf)
{
	int rc;
	    if (!conf->attach_to_pid) {
	        rc = map_new_buffers(conf);
	    }  else {
	        rc = map_buffer(conf, atoi(conf->attach_to_pid));
	    }

	    if (0 != rc) {
	    	rc = errno;
	    	ERR("Failed to attach to buffers, error code =", rc);
	        syslog(LOG_USER|LOG_CRIT, "trace_dumper: Attach to buffers failed due to error %d", rc);
	        return -1;
	    }

	    return 0;
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


static const char usage[] = {
    "Usage: %s [params]                                                                                            \n" \
    "                                                                                                              \n" \
    " -h, --help                            Display this help message                                              \n" \
    " -f  --filter [buffer_name]            Filter out specified buffer name                                       \n" \
    " -o  --online                          Show data from buffers as it arrives (slows performance)               \n" \
    " -w  --write-to-file[filename]         Write log records to file                                              \n" \
    " -b  --logdir                          Specify the base log directory trace files are written to              \n" \
    " -p  --pid [pid]                       Attach the specified process                                           \n" \
    " -d  --debug-online                    Display DEBUG records in online mode                                   \n" \
    " -i  --info-online                     Dump info traces online                                                \n" \
    " -a  --warn-online                     Dump warning traces online                                             \n" \
    " -e  --error-online                    Dump error traces online                                               \n" \
    " -s  --syslog                          In online mode, write the entries to syslog instead of displaying them \n" \
    " -q  --quota-size [bytes/percent]      Specify the total number of bytes that may be taken up by trace files  \n" \
    " -r  --record-write-limit [records]    Specify maximal amount of records that can be written per-second (unlimited if not specified)  \n" \
    " -v  --dump-online-statistics          Dump buffer statistics \n"
    "\n"};

static const struct option longopts[] = {
    { "help", 0, 0, 'h'},
	{ "filter", required_argument, 0, 'f'},
	{ "online", 0, 0, 'o'},
    { "trace-online", 0, 0, 't'},
    { "debug-online", 0, 0, 'd'},
    { "info-online", 0, 0, 'i'},
    { "warn-online", 0, 0, 'a'},
    { "error-online", 0, 0, 'e'},
    { "logdir", required_argument, 0, 'b'},
	{ "no-color", 0, 0, 'n'},
    { "syslog", 0, 0, 's'},
    { "pid", required_argument, 0, 'p'},
    { "write", optional_argument, 0, 'w'},
    { "quota-size", required_argument, 0, 'q'},
    { "record-write-limit", required_argument, 0, 'r'},
    { "dump-online-statistics", 0, 0, 'v'},

	{ 0, 0, 0, 0}
};

static void print_usage(const char *prog_name)
{
	const char *display_name = (NULL == prog_name) ? "trace_dumper" : prog_name;
    printf(usage, display_name);
}

static const char shortopts[] = "vtdiaer:q:sw::p:hf:ob:n";

#define DEFAULT_LOG_DIRECTORY "/mnt/logs/traces"
static void clear_mapped_records(struct trace_dumper_configuration_s *conf)
{
    MappedBuffers__init(&conf->mapped_buffers);
}

static void add_buffer_filter(struct trace_dumper_configuration_s *conf, char *buffer_name)
{
    buffer_name_t filter;
    memset(filter, 0, sizeof(filter));
    strncpy(filter, buffer_name, sizeof(filter));
    
    if (0 != BufferFilter__add_element(&conf->filtered_buffers, &filter)) {
        ERR("Can't add buffer", buffer_name,  "to filter list");
    }
}

static int parse_commandline(struct trace_dumper_configuration_s *conf, int argc, char **argv)
{
    int o;
    while ((o = getopt_long(argc, argv, shortopts, longopts, 0)) != EOF) {
		switch (o) {
		case 'h':
			break;
		case 'f':
			add_buffer_filter(conf, optarg);
			break;
        case 'o':
            conf->online = 1;
            break;
        case 'b':
            conf->logs_base = optarg;
            break;
        case 'n':
            conf->no_color_specified = 0;
            break;
        case 'p':
            conf->attach_to_pid = optarg;
            break;
        case 'w':
            conf->write_to_file = 1;
            conf->fixed_output_filename = optarg;
            break;
        case 's':
            conf->syslog = 1;
            break;
        case 'q':
            conf->quota_specification = optarg;
            break;
        case 'r':
            conf->max_records_per_second = atoi(optarg);
            break;
        case 't':
            conf->trace_online = 1;
            break;
        case 'd':
            conf->debug_online = 1;
            break;
        case 'i':
            conf->info_online = 1;
            break;
        case 'a':
            conf->warn_online = 1;
            break;
        case 'e':
            conf->error_online = 1;
            break;
        case 'v':
            conf->dump_online_statistics = 1;
            break;
        case '?':
            return -1;
            break;
        default:
            break;
        }
    }

    return 0;
}

#define ROTATION_COUNT 10
#define FLUSH_DELTA 5000

static int parser_event_handler(trace_parser_t __attribute__((unused)) *parser, enum trace_parser_event_e __attribute__((unused))event, void __attribute__((unused))*event_data, void __attribute__((unused)) *arg)
{
    return 0;
}

static unsigned long long calculate_free_percentage(unsigned int percent, const char *logdir)
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

static unsigned long long parse_quota_specification(const char *quota_specification, const char *logdir)
{
    unsigned long long max_bytes;
    if (quota_specification[0] == '%') {
        max_bytes = calculate_free_percentage(atoi(&quota_specification[1]), logdir);
    } else {
        max_bytes = atoi(quota_specification);
    }

    max_bytes = max_bytes / sizeof(struct trace_record);
    return max_bytes;
}


static int set_quota(struct trace_dumper_configuration_s *conf)
{
    if (conf->quota_specification) {
        conf->max_records_per_logdir = parse_quota_specification(conf->quota_specification, conf->logs_base);
        if (conf->max_records_per_logdir == 0) {
            return -1;
        }
        
        if (conf->max_records_per_logdir < TRACE_PREFERRED_FILE_MAX_RECORDS_PER_FILE) {
            conf->max_records_per_file = conf->max_records_per_logdir / PREFERRED_NUMBER_OF_TRACE_HISTORY_FILES;
        } else {
            conf->max_records_per_file = TRACE_PREFERRED_FILE_MAX_RECORDS_PER_FILE;
        }
    } else {
        conf->max_records_per_file = TRACE_PREFERRED_FILE_MAX_RECORDS_PER_FILE;
        conf->max_records_per_logdir = TRACE_PREFERRED_MAX_RECORDS_PER_LOGDIR;
    }

    return 0;
}

static void set_default_online_severities(struct trace_dumper_configuration_s *conf)
{
    conf->info_online = 1;
    conf->warn_online = 1;
    conf->error_online = 1;
}

static int init_dumper(struct trace_dumper_configuration_s *conf)
{
    clear_mapped_records(conf);

    if (!conf->write_to_file && !conf->online && conf->dump_online_statistics) {
        conf->op_type = OPERATION_TYPE_DUMP_BUFFER_STATS;
    } else {
        conf->op_type = OPERATION_TYPE_DUMP_RECORDS;
    }
    
    if (! conf->logs_base) {
    	conf->logs_base = DEFAULT_LOG_DIRECTORY;
    }

    if ((! conf->fixed_output_filename) && (trace_create_dir_if_necessary(conf->logs_base) != 0)) {
        return EX_CANTCREAT;
    }

    conf->record_file.fd = -1;
    conf->ts_flush_delta = FLUSH_DELTA;
    TRACE_PARSER__from_external_stream(&conf->parser, parser_event_handler, NULL);
    TRACE_PARSER__set_indent(&conf->parser, TRUE);
    TRACE_PARSER__set_show_field_names(&conf->parser, TRUE);

    TRACE_PARSER__set_relative_ts(&conf->parser, TRUE);
    if (conf->no_color_specified) {
        conf->color = 0;
        TRACE_PARSER__set_color(&conf->parser, FALSE);
    } else {
        conf->color = 1;
        TRACE_PARSER__set_color(&conf->parser, TRUE);
    }
    
    if (conf->syslog) {
        openlog("traces", 0, 0);
        TRACE_PARSER__set_indent(&conf->parser, 0);
        TRACE_PARSER__set_color(&conf->parser, 0);
        TRACE_PARSER__set_show_timestamp(&conf->parser, 0);
        TRACE_PARSER__set_show_field_names(&conf->parser, 0);
    }

    unsigned int severity_mask = get_allowed_online_severity_mask(conf);
    if (0 == severity_mask) {
        set_default_online_severities(conf);
        severity_mask = get_allowed_online_severity_mask(conf);
    }
    
    if (conf->trace_online) {
        TRACE_PARSER__set_indent(&conf->parser, TRUE);
    } else {
        TRACE_PARSER__set_indent(&conf->parser, FALSE);
    }

    TRACE_PARSER__matcher_spec_from_severity_mask(severity_mask, conf->severity_filter, ARRAY_LENGTH(conf->severity_filter));
    TRACE_PARSER__set_filter(&conf->parser, conf->severity_filter);

    if (set_quota(conf) != 0) {
        return EX_IOERR;
    }

    return 0;
}

void usr1_handler()
{
    if (trace_dumper_configuration.record_file.fd >= 0) {
        close_record_file(&trace_dumper_configuration);
    }
}

void usr2_handler()
{
    if (trace_dumper_configuration.record_file.fd >= 0) {
        close_record_file(&trace_dumper_configuration);
    }

    char snapshot_filename[0x100];
    char dir[0x100];
    char base[0x100];
    char orig_filename[0x100];
    strncpy(orig_filename, trace_dumper_configuration.record_file.filename, sizeof(orig_filename));
    char *dirname_ptr = dirname(orig_filename);
    strncpy(dir, dirname_ptr, sizeof(dir));
    strncpy(orig_filename, trace_dumper_configuration.record_file.filename, sizeof(orig_filename));
    char *basename_ptr = basename(orig_filename);
    strncpy(base, basename_ptr, sizeof(base));
    snprintf(snapshot_filename, sizeof(snapshot_filename), "%s/snapshot.%s", dir, base);
    int rc = rename(trace_dumper_configuration.record_file.filename, snapshot_filename);
    if (0 != rc) {
        ERR("Error moving",  trace_dumper_configuration.record_file.filename, "to", snapshot_filename, "(", strerror(errno), ")");
    } else {
        INFO("Created snapshot file at", snapshot_filename);
    }
}

static void set_signal_handling(void)
{
    signal(SIGUSR1, usr1_handler);
    signal(SIGUSR2, usr2_handler);
}


int main(int argc, char **argv)
{
    struct trace_dumper_configuration_s *conf = &trace_dumper_configuration;
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

    int rc = init_dumper(&trace_dumper_configuration);
    if (0 != rc) {
    	if (EX_USAGE == rc) {
    		print_usage(argv[0]);
    	}
    	else {
    		fprintf(stderr, "%s failed to start with error code %d (see sysexits.h for its meaning)\n", argv[0], rc);
    	}
        return rc;
    }
    
    set_signal_handling();

    return run_dumper(conf);
}
