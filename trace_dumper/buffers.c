/*
 * buffers.c
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


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <syslog.h>

#include "../bool.h"
#include "../trace_lib.h"
#include "../trace_user.h"
#include "../trace_clock.h"
#include "../trace_str_util.h"
#include "../file_naming.h"
#include "trace_dumper.h"
#include "metadata.h"
#include "open_close.h"
#include "buffers.h"


#define SHM_DIR "/dev/shm"


CREATE_LIST_IMPLEMENTATION(MappedBuffers, struct trace_mapped_buffer);
CREATE_LIST_IMPLEMENTATION(BufferFilter, buffer_name_t);
CREATE_LIST_IMPLEMENTATION(PidList, trace_pid_t);

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
    char *underscore = strchr(shm_name, '_');

    if (NULL == underscore) {
        errno = EINVAL;
        return -1;
    }

    if ((unsigned long) (underscore - shm_name) >= sizeof(str_pid)) {
        errno = EINVAL;
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

static bool_t process_exists(pid_t pid) {
	int saved_errno = errno;
	if (0 == kill(pid, 0)) {
		return TRUE;
	}

	switch (errno) {
	case EPERM:
		errno = saved_errno;
		return TRUE;

	case ESRCH:
		errno = saved_errno;
		break;

	default:
		syslog(LOG_USER|LOG_ERR, "Failed to check for the existence of pid %d due to %s", pid, strerror(errno));
		break;
	}

	return FALSE;
}

static int stat_pid(pid_t pid, struct stat *stat_buf)
{
    char filename[0x100];
    snprintf(filename, sizeof(filename), "/proc/%d", pid);
    return stat(filename, stat_buf);
}

static int get_process_time(pid_t pid, trace_ts_t *curtime)
{
	if (NULL == curtime) {
		errno = EFAULT;
		return -1;
	}

    struct stat stat_buf;
    int rc = stat_pid(pid, &stat_buf);
    if (0 != rc) {
    	if (ENOENT == errno) {
    		errno = ESRCH;
    	}
    	return -1;
    }

    *curtime = stat_buf.st_ctim.tv_sec * TRACE_SECOND + stat_buf.st_ctim.tv_nsec;
    return 0;
}

bool_t trace_should_filter(struct trace_dumper_configuration_s *conf, const char *buffer_name)
{
    buffer_name_t filter;
    memset(filter, 0, sizeof(filter));
    trace_strncpy_and_terminate(filter, buffer_name, sizeof(filter));
    int rc = BufferFilter__find_element(&conf->filtered_buffers, &filter);
    return rc >= 0 ;
}

/* Open a shared memory object in read-write mode and return the file descriptor. Also if size is not NULL, return its size */
static int open_trace_shm(const char *shm_name, off_t *size) {
	int fd = shm_open(shm_name, O_RDWR, 0);
	if (fd < 0) {
		syslog(LOG_USER|LOG_ERR, "Failed to open the trace shared-memory object %s due to error: %s", shm_name, strerror(errno));
	}

	else if (NULL != size) {
		struct stat st;
		int rc = fstat(fd, &st);
		if (rc < 0) {
			syslog(LOG_USER|LOG_ERR, "Failed to obtain the size of the trace shared-memory object %s due to error: %s", shm_name, strerror(errno));
			close(fd);
			*size = 0;
			return rc;
		}
		*size = st.st_size;
	}

	return fd;
}

static int map_buffer(struct trace_dumper_configuration_s *conf, pid_t pid)
{
    int static_fd = -1, dynamic_fd = -1;
    char dynamic_trace_filename[0x100];
    char static_log_data_filename[0x100];
    int rc = -1;
    struct trace_mapped_buffer *new_mapped_buffer = NULL;
    snprintf(dynamic_trace_filename, sizeof(dynamic_trace_filename), TRACE_DYNAMIC_DATA_REGION_NAME_FMT, pid);
    snprintf(static_log_data_filename, sizeof(static_log_data_filename), TRACE_STATIC_DATA_REGION_NAME_FMT, pid);

    off_t static_log_data_region_size = 0;
    static_fd = open_trace_shm(static_log_data_filename, &static_log_data_region_size);
    if (static_fd < 0) {
        ERR("Unable to open static buffer:", static_log_data_filename, pid, errno, strerror(errno));
        rc = -1;
        goto delete_shm_files;
    }

    off_t trace_region_size = 0;
    dynamic_fd = open_trace_shm(dynamic_trace_filename, &trace_region_size);
    if (dynamic_fd < 0) {
        ERR("Unable to open dynamic buffer", dynamic_trace_filename, pid, errno, strerror(errno));
        rc = -1;
        goto close_static;
    }

    void *mapped_dynamic_addr = mmap(NULL, trace_region_size, PROT_READ | PROT_WRITE, MAP_SHARED, dynamic_fd, 0);
    if (MAP_FAILED == mapped_dynamic_addr) {
        ERR("Unable to map log information buffer", dynamic_trace_filename, pid, errno, strerror(errno));
        rc = -1;
        goto close_dynamic;
    }

    void * mapped_static_log_data_addr = mmap(NULL, static_log_data_region_size, PROT_READ | PROT_WRITE, MAP_SHARED, static_fd, 0);
    if (MAP_FAILED == mapped_static_log_data_addr) {
        ERR("Unable to map static log area:", static_log_data_filename, pid, errno, strerror(errno));
        rc = -1;
        goto unmap_dynamic;
    }

    struct trace_buffer *unmapped_trace_buffer = (struct trace_buffer *) mapped_dynamic_addr;
    struct trace_metadata_region *static_log_data_region = (struct trace_metadata_region *) mapped_static_log_data_addr;

    if (trace_should_filter(conf, static_log_data_region->name)) {
        rc = 0;
        INFO("Filtering buffer", static_log_data_region->name, pid);
        goto unmap_static;

    }

    if (0 != MappedBuffers__allocate_element(&conf->mapped_buffers)) {
        rc = -1;
        ERR("No space left to add a buffer for", static_log_data_region->name, pid);
        goto unmap_static;
    }

    assert(0 == MappedBuffers__get_element_ptr(&conf->mapped_buffers, MappedBuffers__element_count(&conf->mapped_buffers) - 1, &new_mapped_buffer));
    memset(new_mapped_buffer, 0, sizeof(*new_mapped_buffer));
    if (static_log_data_region_size > MAX_METADATA_SIZE) {
        ERR("Error, metadata size too large for", static_log_data_region->name, pid, static_log_data_region_size);
        rc = -1;
        goto remove_mapped_buffer;
    }

    new_mapped_buffer->records_buffer_base_address = mapped_dynamic_addr;
    new_mapped_buffer->record_buffer_fd = dynamic_fd;
    new_mapped_buffer->records_buffer_size = trace_region_size;
    new_mapped_buffer->metadata.log_descriptor_count = static_log_data_region->log_descriptor_count;
    new_mapped_buffer->metadata.type_definition_count = static_log_data_region->type_definition_count;
    new_mapped_buffer->metadata.descriptors = (struct trace_log_descriptor *) static_log_data_region->data;
    new_mapped_buffer->metadata.size = static_log_data_region_size;
    new_mapped_buffer->metadata.base_address = mapped_static_log_data_addr;
    new_mapped_buffer->metadata.metadata_fd = static_fd;
    new_mapped_buffer->pid = (trace_pid_t) pid;
    new_mapped_buffer->metadata_dumped = FALSE;
    new_mapped_buffer->notification_metadata_dumped = FALSE;
    trace_ts_t process_time;
    rc = get_process_time(pid, &process_time);
    if (0 != rc) {
    	if (ESRCH == errno) {
    		rc = 0;
    		WARN("Process", pid, "no longer exists");
    	}
    	else {
    		syslog(LOG_USER|LOG_WARNING, "Failed to get the process time for pid %d due to %s", pid, strerror(errno));
    	}
    	process_time = 0;
    }

    new_mapped_buffer->process_time = process_time;
    relocate_metadata(static_log_data_region->base_address, mapped_static_log_data_addr, (char *) new_mapped_buffer->metadata.descriptors,
                      new_mapped_buffer->metadata.log_descriptor_count, new_mapped_buffer->metadata.type_definition_count);
    static_log_data_region->base_address = mapped_static_log_data_addr;
    init_metadata_iovector(&new_mapped_buffer->metadata, new_mapped_buffer->pid);
    trace_array_strcpy(new_mapped_buffer->name, static_log_data_region->name);
    unsigned int i;
    for (i = 0; i < TRACE_BUFFER_NUM_RECORDS; i++) {
        struct trace_mapped_records *mapped_records;

        mapped_records = &new_mapped_buffer->mapped_records[i];
        mapped_records->records = unmapped_trace_buffer->u._all_records[i].records;
        mapped_records->mutab = &unmapped_trace_buffer->u._all_records[i].mutab;
        mapped_records->imutab = &unmapped_trace_buffer->u._all_records[i].imutab;
        mapped_records->last_flush_offset = 0;
        mapped_records->current_read_record = mapped_records->mutab->next_flush_record;
    }

    if (new_mapped_buffer->pid != pid) {
        WARN("Pid cannot fit in a 16-bit field for", new_mapped_buffer->name, pid, mapped_static_log_data_addr, static_log_data_region_size, mapped_dynamic_addr, trace_region_size);
    	syslog(LOG_USER|LOG_WARNING, "Pid %d of %s is too large to be represented in trace dumper's %lu-bit pid field. Please restrict your system's process IDs accordingly",
    			pid, new_mapped_buffer->name, 8*sizeof(new_mapped_buffer->pid));
    }
    else if (conf->log_details && !conf->attach_to_pid) {
        INFO("Starting to collect traces from the process", new_mapped_buffer->name, pid, mapped_static_log_data_addr, static_log_data_region_size, mapped_dynamic_addr, trace_region_size);
    	syslog(LOG_USER|LOG_INFO, "Starting to collect traces from %s with pid %d to %s",
    			new_mapped_buffer->name, new_mapped_buffer->pid, conf->record_file.filename);
    }

    rc = 0;
    goto exit;

remove_mapped_buffer:
    MappedBuffers__remove_element(&conf->mapped_buffers, MappedBuffers__last_element_index(&conf->mapped_buffers));
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
    if ((ENOENT == errno) && !process_exists(pid)) {
        errno = ESRCH;
    }

	if (0 != rc) {
		const char *err_name = strerror(errno);
		const char *proc_name = ((NULL == new_mapped_buffer) ? "(unknown)" : new_mapped_buffer->name);
		ERR("Failed to map a buffer for process", proc_name, pid, errno, err_name);
		syslog(LOG_USER|LOG_ERR, "Failed to map buffer for pid %d - %s. Last Error: %s.", (int) pid, proc_name, err_name);
	}
	return rc;
}

static bool_t buffer_mapped(struct trace_dumper_configuration_s * conf, unsigned short pid)
{
    int i;
    for (i = 0; i < MappedBuffers__element_count(&conf->mapped_buffers); i++) {
        struct trace_mapped_buffer *mapped_buffer;
        assert(0 == MappedBuffers__get_element_ptr(&conf->mapped_buffers, i, &mapped_buffer));
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

int map_new_buffers(struct trace_dumper_configuration_s *conf)
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

static void check_discarded_buffer(const struct trace_mapped_buffer *mapped_buffer)
{
	struct trace_records_mutable_metadata mutab;
	memcpy(&mutab, (const void *)(mapped_buffer->mapped_records->mutab), sizeof(mutab));
	const volatile struct trace_record *last_rec = &mapped_buffer->mapped_records->records[mutab.last_committed_record & mapped_buffer->mapped_records->imutab->max_records_mask];

	bool_t buffer_was_active = (-1UL != mutab.last_committed_record);
	trace_pid_t pid = mapped_buffer->pid;
	const char * proc_name = mapped_buffer->name;

	if (mapped_buffer->dead) {
		assert(mutab.last_committed_record + 1UL == mapped_buffer->mapped_records->next_flush_record);
		assert(mutab.last_committed_record + 1UL == mapped_buffer->mapped_records->current_read_record);
		if (buffer_was_active) {
			assert(mutab.latest_flushed_ts == last_rec->ts);
		}
	}

	if (buffer_was_active) {
		if (! (last_rec->termination & TRACE_TERMINATION_LAST)) {
			syslog(LOG_USER|LOG_WARNING, "While discarding the buffer for %s (pid %d) found that the last record number %lu was untermintated",
					proc_name, pid, mutab.last_committed_record);
		}
	}

	trace_record_counter_t uncommitted_records = mutab.current_record - mutab.last_committed_record - 1;
	if (uncommitted_records > 0) {
		syslog(LOG_USER|LOG_WARNING, "The process %s (pid %d) has died leaving %lu records allocated but not committed",
				proc_name, pid, uncommitted_records);
	}
}

#define REPORT_BUF_ERR(descr) do { \
    ERR(descr " for buffer pid=", mapped_buffer->pid, mapped_buffer->name, "errno=", errno, strerror(errno)); \
    syslog(LOG_USER|LOG_WARNING, descr " for buffer %s (pid %u) errno=%d - %s", mapped_buffer->name, mapped_buffer->pid, errno, strerror(errno)); \
    } while (0)

/* Immediately discard all the dumper resources for a buffer regardless of whether or not the traced process has ended. */
static void discard_buffer_unconditionally(struct trace_mapped_buffer *mapped_buffer)
{
    free_metadata(&mapped_buffer->metadata);

    int rc = munmap(mapped_buffer->metadata.base_address, mapped_buffer->metadata.size);
    if (0 == rc) {
    	mapped_buffer->metadata.base_address = MAP_FAILED;
    }
    else {
        REPORT_BUF_ERR("Error unmapping metadata for buffer");
    }

    rc = close(mapped_buffer->metadata.metadata_fd);
    if (0 == rc) {
    	mapped_buffer->metadata.metadata_fd = -1;
    }
    else {
        REPORT_BUF_ERR("Error closing metadata");
	}

    rc = munmap(mapped_buffer->records_buffer_base_address, mapped_buffer->records_buffer_size);
    if (0 == rc) {
    	mapped_buffer->records_buffer_base_address = MAP_FAILED;
    }
    else {
        REPORT_BUF_ERR("Error unmapping records for buffer");
    }

    rc = close(mapped_buffer->record_buffer_fd);
	if (0 == rc) {
		mapped_buffer->record_buffer_fd = -1;
	}
	else {
	    REPORT_BUF_ERR("Error closing records for buffer");
	}
}

/* Discard all the dumper resources the trace buffer of a process that has ended. */
void discard_buffer(struct trace_dumper_configuration_s *conf, struct trace_mapped_buffer *mapped_buffer)
{
    INFO("Discarding pid", mapped_buffer->pid, mapped_buffer->name);
    check_discarded_buffer(mapped_buffer);

    discard_buffer_unconditionally(mapped_buffer);

    int rc = delete_shm_files(mapped_buffer->pid);
    if (0 != rc) {
        REPORT_BUF_ERR("Error deleting shm files");
    }

    if (conf->trace_online && (TRACE_PARSER__free_buffer_context_by_pid(&(conf->parser), mapped_buffer->pid) < 0)) {
        REPORT_BUF_ERR("Failed to free trace parser resources");
    }

    if (! PidList__insertable(&conf->dead_pids)) {
        WARN("Trace dumper has too many pids pending removal, exceeding the limit of",  (int)PidList_NUM_ELEMENTS,
                ". Not enough space to insert pid", mapped_buffer->pid, mapped_buffer->name);
    	syslog(LOG_USER|LOG_WARNING, "Trace dumper has too many pids pending removal, exceeding the limit of %d. Not enough space to insert pid %u for process %s",
    			PidList_NUM_ELEMENTS, mapped_buffer->pid, mapped_buffer->name);
    }
    else {
    	PidList__add_element(&conf->dead_pids, &mapped_buffer->pid);
    }

    struct trace_mapped_buffer *tmp_mapped_buffer;
    int i;
    int removed_count = 0;
    for_each_mapped_buffer(i, tmp_mapped_buffer) {
        if (mapped_buffer == tmp_mapped_buffer) {
            MappedBuffers__remove_element(&conf->mapped_buffers, i);
            removed_count++;
        }
    }

    int buffers_remaining = MappedBuffers__element_count(&conf->mapped_buffers);
    syslog(LOG_USER|LOG_INFO, "Discarded %d instance(s) of the buffer for %s pid %u, %d mapped buffer(s) remaining",
    		removed_count,  mapped_buffer->name, mapped_buffer->pid, buffers_remaining);
}

#undef REPORT_BUF_ERR

void discard_all_buffers_immediately(struct trace_dumper_configuration_s *conf)
{
	int i;
	struct trace_mapped_buffer *mapped_buffer;
	for_each_mapped_buffer(i, mapped_buffer) {
		discard_buffer_unconditionally(mapped_buffer);
	}

	clear_mapped_records(conf);
	close_all_files(conf);
	return;
}

/* Mark all the records written as committed, so that any records that may have been written, even if incomplete, will be flushed.
 * This is especially important if the traced process dies due to a fatal signal. */
static void adjust_buffer_for_final_dumping(struct trace_mapped_buffer *mapped_buffer)
{
	int i;
	for (i = 0; i < TRACE_BUFFER_NUM_RECORDS; i++) {
		volatile struct trace_records_mutable_metadata *mutab =  mapped_buffer->mapped_records[i].mutab;
		mutab->last_committed_record = mutab->current_record - 1;
	}
}

int unmap_discarded_buffers(struct trace_dumper_configuration_s *conf)
{
    int i;
    struct trace_mapped_buffer *mapped_buffer;
    for_each_mapped_buffer(i, mapped_buffer) {
        if (!process_exists(mapped_buffer->pid)) {
        	adjust_buffer_for_final_dumping(mapped_buffer);
            mapped_buffer->dead = 1;
        }
    }

    return 0;
}

int attach_and_map_buffers(struct trace_dumper_configuration_s *conf)
{
	int rc;
	    if (!conf->attach_to_pid) {
	        rc = map_new_buffers(conf);
	    }  else {
	        const pid_t target_pid = atoi(conf->attach_to_pid);
	        if (target_pid <= 0) {
	            errno = EINVAL;
	            rc = -1;
	        }
	        else do {
	            rc = map_buffer(conf, target_pid);
	            if ((0 == rc) || (ENOENT != errno)) {
	                break;
	            }
	            const useconds_t retry_interval_ms = 10;
	            usleep(1000 * retry_interval_ms);
	        } while(process_exists(target_pid));
	    }

	    if (0 != rc) {
	    	rc = errno;
	    	ERR("Failed to attach to buffers, error code =", rc);
	        syslog(LOG_USER|LOG_CRIT, "trace_dumper: Attach to buffers failed due to error %d", rc);
	        return -1;
	    }

	    return 0;
}


bool_t has_mapped_buffers(const struct trace_dumper_configuration_s *conf)
{
    return MappedBuffers__element_count(&conf->mapped_buffers) > 0;
}

void clear_mapped_records(struct trace_dumper_configuration_s *conf)
{
    MappedBuffers__init(&conf->mapped_buffers);
    PidList__init(&conf->dead_pids);
}

void add_buffer_filter(struct trace_dumper_configuration_s *conf, char *buffer_name)
{
    buffer_name_t filter;
    trace_strncpy_and_terminate(filter, buffer_name, sizeof(filter));

    if (0 != BufferFilter__add_element(&conf->filtered_buffers, &filter)) {
        ERR("Can't add buffer", buffer_name,  "to filter list");
    }
}
