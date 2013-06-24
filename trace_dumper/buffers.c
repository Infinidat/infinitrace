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

#include "../platform.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <syslog.h>

#include "../trace_lib.h"
#include "../trace_user.h"
#include "../trace_clock.h"
#include "../trace_str_util.h"
#include "../file_naming.h"
#include "../trace_proc_util.h"
#include "../trace_mmap_util.h"
#include "trace_dumper.h"
#include "metadata.h"
#include "open_close.h"
#include "buffers.h"



CREATE_LIST_IMPLEMENTATION(MappedBuffers, struct trace_mapped_buffer);
CREATE_LIST_IMPLEMENTATION(BufferFilter, buffer_name_t);
CREATE_LIST_IMPLEMENTATION(PidList, trace_pid_t);

bool_t is_trace_shm_region(const char *shm_name)
{
    return trace_str_starts_with_prefix(shm_name, TRACE_SHM_ID);
}

static bool_t is_dynamic_log_data_shm_region(const char *shm_name)
{
    return trace_str_ends_with_suffix(shm_name, TRACE_DYNAMIC_SUFFIX);
}

/* Obtain the process time for active process, or return 0 if the process had exited or cannot have its time obtained for whatever reason */
static trace_ts_t get_effective_process_time(pid_t pid)
{
    trace_ts_t process_time = 0;
    if (0 != trace_get_process_time(pid, &process_time)) {
        if (ESRCH == errno) {
            INFO("About to start collecting traces from the defunct process", pid);
        }
        else {
            const int err = errno;
            syslog(LOG_USER|LOG_WARNING, "Failed to get the process time for pid %d due to %s", pid, strerror(err));
            WARN("Failed to get the process time for", pid, err, strerror(err));
        }
    }

    return process_time;
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
	    const int err = errno;
		syslog(LOG_USER|LOG_ERR, "Failed to open the trace shared-memory object %s due to error: %s", shm_name, strerror(err));
		ERR("Failed to open the trace shared-memory object", shm_name, err, strerror(err));
	}

	else if (NULL != size) {
		struct stat st;
		int rc = fstat(fd, &st);
		if (rc < 0) {
		    const int err = errno;
			syslog(LOG_USER|LOG_ERR, "Failed to obtain the size of the trace shared-memory object %s due to error: %s", shm_name, strerror(err));
			ERR("Failed to obtain the size of the trace shared-memory", shm_name, err, strerror(err));
			close(fd);
			*size = 0;
			return rc;
		}
		*size = st.st_size;
	}

	return fd;
}

static void *map_single_buffer(pid_t pid, enum trace_shm_object_type shm_type, off_t *shm_size)
{
    trace_shm_name_buf name;
    assert(trace_generate_shm_name(name, pid, shm_type, FALSE) > 0);

    off_t size = 0;
    const int fd = open_trace_shm(name, &size);
    if (fd < 0) {
        const int err = errno;
        ERR("Unable to open buffer", name, pid, err, strerror(err));
        return MAP_FAILED;
    }

    void *addr = MAP_FAILED;
    if (size > 0) {
        addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    }
    else {
        errno = EINVAL;
        ERR("Invalid buffer file with size 0", name, pid);
    }

    if (0 != close(fd)) {
        const int err = errno;
        ERR("Failed to close fd for the mapped buffer", name, fd, addr, err, strerror(err), "unmapping the buffer");
        goto unmap_shm;
    }

    if (MAP_FAILED == addr) {
        const int err = errno;
        ERR("Unable to map the buffer", name, fd, TRACE_NAMED_INT_AS_HEX(size), err, strerror(err));
        TRACE_ASSERT(0 != err);
        return MAP_FAILED;
    }

#ifdef MADV_DONTFORK
    if (madvise(addr, size, MADV_DONTFORK) < 0) {
        const int err = errno;
        ERR("Failed to set MADV_DONTFORK for buffer", name, fd, addr, TRACE_NAMED_INT_AS_HEX(size), err, strerror(err));
        goto unmap_shm;
    }
#endif

    INFO("Successfully mapped the buffer", pid, shm_type, name, addr, TRACE_NAMED_INT_AS_HEX(size));
    if (NULL != shm_size) {
        *shm_size = size;
    }
    return addr;

unmap_shm:
    trace_munmap_if_necessary(&addr, size);
    return MAP_FAILED;
}

static void init_mapped_records_from_trace_records(struct trace_mapped_records *const mapped_records, struct trace_records *trace_recs)
{
    mapped_records->records = trace_recs->records;
    mapped_records->imutab  = &trace_recs->imutab;
    mapped_records->mutab   = &trace_recs->mutab;
    mapped_records->last_flush_offset = 0;
    mapped_records->current_read_record = mapped_records->mutab->next_flush_record;
    mapped_records->next_flush_record   = mapped_records->current_read_record;
}

static int map_buffer(struct trace_dumper_configuration_s *conf, pid_t pid)
{
    int rc = -1;
    struct trace_mapped_buffer *new_mapped_buffer = NULL;
    if (0 != MappedBuffers__allocate_element(&conf->mapped_buffers)) {
        ERR("No space left to add a buffer for", pid);
        rc = -1;
        goto delete_shm_files;  /* TODO: Reconsider this, perhaps we should wait and avoid flooding with messages in the meantime */
    }

    TRACE_ASSERT(0 == MappedBuffers__get_element_ptr(&conf->mapped_buffers, MappedBuffers__element_count(&conf->mapped_buffers) - 1, &new_mapped_buffer));
    memset(new_mapped_buffer, 0, sizeof(*new_mapped_buffer));

    off_t static_log_data_region_size = 0;
    struct trace_metadata_region *const static_log_data_region =
            (struct trace_metadata_region *) map_single_buffer(pid, TRACE_SHM_TYPE_STATIC, &static_log_data_region_size);
    if (MAP_FAILED == static_log_data_region) {
        ERR("Unable to map static log area:", pid, errno, strerror(errno));
        rc = -1;
        goto remove_mapped_buffer;
    }

    if (trace_should_filter(conf, static_log_data_region->name)) {
        rc = 0;
        INFO("Filtering buffer", static_log_data_region->name, pid);
        goto unmap_static;
    }

    /* The static metadata region uses internal pointers that are valid in the address-space of the client process, where the metadata region
     * had been mapped at static_log_data_region->base_address. We have to adjust them to the dumper's address space, where the same region
     * is now mapped at static_log_data_region, and update the base_address field with the new base address relative to which the pointers are now valid. */
    const void *const client_base_addr = static_log_data_region->base_address;
    if ((static_log_data_region_size > MAX_METADATA_SIZE) || (static_log_data_region_size < (off_t) sizeof(*static_log_data_region)) || (NULL == client_base_addr)) {
        ERR("Metadata bad size or invalid base address for", static_log_data_region->name, pid, static_log_data_region_size, client_base_addr);
        rc = -1;
        goto unmap_static;
    }

    new_mapped_buffer->metadata.log_descriptor_count = static_log_data_region->log_descriptor_count;
    new_mapped_buffer->metadata.type_definition_count = static_log_data_region->type_definition_count;
    new_mapped_buffer->metadata.descriptors = (struct trace_log_descriptor *) static_log_data_region->data;
    new_mapped_buffer->metadata.size = static_log_data_region_size;
    new_mapped_buffer->metadata.base_address = static_log_data_region;

    relocate_metadata(client_base_addr, static_log_data_region, (char *) new_mapped_buffer->metadata.descriptors,
                      new_mapped_buffer->metadata.log_descriptor_count, new_mapped_buffer->metadata.type_definition_count);
    static_log_data_region->base_address = static_log_data_region;
    if (mprotect(static_log_data_region, static_log_data_region_size, PROT_READ) < 0) {
        const int err = errno;
        ERR("Failed to make the static log data region", static_log_data_region, static_log_data_region_size, "read-only.", err, strerror(err));
        goto unmap_static;
    }

    off_t trace_region_size = 0;
    struct trace_buffer *const dynamic_trace_buffer =
            (struct trace_buffer *) map_single_buffer(pid, TRACE_SHM_TYPE_DYNAMIC, &trace_region_size);
    if (MAP_FAILED == dynamic_trace_buffer) {
        ERR("Unable to map log information buffer", pid, errno, strerror(errno));
        rc = -1;
        goto unmap_static;
    }

    if (pid != dynamic_trace_buffer->pid) {
        ERR("Dynamic buffer pid", dynamic_trace_buffer->pid, "inconsistent with the one implied by its name", pid);
        errno = EUCLEAN;
        goto unmap_dynamic;
    }

    new_mapped_buffer->records_buffer_base_address = dynamic_trace_buffer;
    new_mapped_buffer->records_buffer_size = trace_region_size;
    new_mapped_buffer->pid = (trace_pid_t) pid;
    new_mapped_buffer->metadata_dumped = FALSE;
    new_mapped_buffer->notification_metadata_dumped = FALSE;
    new_mapped_buffer->process_time = get_effective_process_time(pid);

    if (dynamic_trace_buffer->n_record_buffers <= 0) {
        errno = EINVAL;
        ERR("Bad number of record buffers", dynamic_trace_buffer->n_record_buffers, "for dynamic buffer of", pid, static_log_data_region->name);
        goto unmap_dynamic;
    }
    new_mapped_buffer->n_record_buffers = dynamic_trace_buffer->n_record_buffers;
    new_mapped_buffer->mapped_records = calloc(new_mapped_buffer->n_record_buffers, sizeof(new_mapped_buffer->mapped_records[0]));
    if (NULL == new_mapped_buffer->mapped_records) {
        ERR("Dynamic memory allocation failed", pid, static_log_data_region->name);
        goto unmap_dynamic;
    }

    init_metadata_iovector(&new_mapped_buffer->metadata, new_mapped_buffer->pid);
    trace_array_strcpy(new_mapped_buffer->name, static_log_data_region->name);
    int i;
    for (i = 0; i < new_mapped_buffer->n_record_buffers; i++) {
        init_mapped_records_from_trace_records(new_mapped_buffer->mapped_records + i, dynamic_trace_buffer->u._all_records + i);
    }

    INFO("Starting to collect traces from the process", new_mapped_buffer->name, pid, static_log_data_region, static_log_data_region_size, dynamic_trace_buffer, trace_region_size);
    if (new_mapped_buffer->pid != pid) {
        WARN("Pid cannot fit in a ", 8*sizeof(new_mapped_buffer->pid), "bit field for", new_mapped_buffer->name, pid, static_log_data_region, static_log_data_region_size, dynamic_trace_buffer, trace_region_size);
    	syslog(LOG_USER|LOG_WARNING, "Pid %d of %s is too large to be represented in trace dumper's %lu-bit pid field. Please restrict your system's process IDs accordingly",
    			pid, new_mapped_buffer->name, 8*sizeof(new_mapped_buffer->pid));
    }
    else if (conf->log_details && !conf->attach_to_pid) {
    	syslog(LOG_USER|LOG_INFO, "Starting to collect traces from %s with pid %d to %s",
    			new_mapped_buffer->name, new_mapped_buffer->pid, conf->record_file.filename);
    }

    return 0;

unmap_dynamic:
    TRACE_ASSERT(trace_region_size > 0);
    if (munmap(dynamic_trace_buffer, trace_region_size) < 0) {
        const int err = errno;
        ERR("Failed to unmap the dynamic buffer", dynamic_trace_buffer, trace_region_size, pid, new_mapped_buffer->name, err, strerror(err));
        rc = -1;
    }

unmap_static:
    TRACE_ASSERT(static_log_data_region_size > 0);
    if (munmap(static_log_data_region, static_log_data_region_size) < 0) {
        const int err = errno;
        ERR("Failed to unmap the static buffer", static_log_data_region, static_log_data_region_size, pid, new_mapped_buffer->name, err, strerror(err));
        rc = -1;
    }

remove_mapped_buffer:
    {
        const char *const proc_name = (NULL == new_mapped_buffer) ? "(unknown)" : new_mapped_buffer->name;
        WARN("Failed to attach to the process", pid, proc_name, "Removing the data structures for it.");
    }
    TRACE_ASSERT(0 == MappedBuffers__remove_element(&conf->mapped_buffers, MappedBuffers__last_element_index(&conf->mapped_buffers)));

delete_shm_files:
    WARN("The shared-memory areas for the process", pid, "could not be open and will be deleted.");
    if (delete_shm_files(pid) < 0) {
        const int err = errno;
        ERR("Failed to delete shared-memory files for", pid, err, strerror(err));
        rc = -1;
    }

	if (0 != rc) {
	    if ((ENOENT == errno) && !trace_process_exists(pid)) {
	        errno = ESRCH;
	    }
	    const int err = errno;
		const char *err_name = strerror(err);
		ERR("Failed to map a buffer for process", pid, err, err_name);
		syslog(LOG_USER|LOG_ERR, "Failed to map buffer for pid %d. Last Error: %s.", (int) pid, err_name);
	}
	return rc;
}

static bool_t buffer_mapped(struct trace_dumper_configuration_s * conf, pid_t pid)
{
    int i;
    for (i = 0; i < MappedBuffers__element_count(&conf->mapped_buffers); i++) {
        struct trace_mapped_buffer *mapped_buffer;
        TRACE_ASSERT(0 == MappedBuffers__get_element_ptr(&conf->mapped_buffers, i, &mapped_buffer));
        if (mapped_buffer->pid == pid) {
            return TRUE;
        }
    }

    return FALSE;
}

static bool_t process_is_child_of_mapped_process(struct trace_dumper_configuration_s *conf, pid_t pid)
{
    int num_pids = MappedBuffers__element_count(&conf->mapped_buffers);
    pid_t pids[num_pids];

    struct trace_mapped_buffer *mapped_buffer = NULL;
    int i;
    for_each_mapped_buffer(i, mapped_buffer) {
        pids[i] = mapped_buffer->pid;
        if (pids[i] == pid) {
            return TRUE;
        }
    }

    return trace_is_process_descended_from_pids(pid, pids, num_pids);
}

static int process_potential_trace_buffer(struct trace_dumper_configuration_s *conf, const char *shm_name)
{
    if (  is_trace_shm_region(shm_name) &&
          is_dynamic_log_data_shm_region(shm_name)) {
        const pid_t pid = trace_get_pid_from_shm_name(shm_name);
        if (pid <= 0) {
            return -1;
        }
        else if (buffer_mapped(conf, pid)) {
            return 0;
        }
        else if ((conf->attach_to_pid > 0) && (conf->attach_to_pid != pid) && !process_is_child_of_mapped_process(conf, pid)) {
            return 0;
        }

        return map_buffer(conf, pid);
    }

    return 0;
}

int map_new_buffers(struct trace_dumper_configuration_s *conf)
{
    DIR *dir;
    struct dirent *ent;
    int rc = 0;
    dir = opendir(SHM_DIR);

    if (dir == NULL) {
        const int err = errno;
    	syslog(LOG_USER|LOG_ERR, "Failed to access the shared-memory directory " SHM_DIR);
    	ERR("Failed to access the shared-memory directory " SHM_DIR, err, strerror(err));
    	return -1;
    }

    while (TRUE) {
        ent = readdir(dir);
        if (NULL == ent) {
            break;
        }

        rc = process_potential_trace_buffer(conf, ent->d_name);
        if (0 != rc) {
            const int err = errno;
        	syslog(LOG_USER|LOG_ERR, "Failed to process the trace buffer %s.", ent->d_name);
            ERR("Error processing trace buffer", ent->d_name, err, strerror(err));
            continue;
        }
    }

    closedir(dir);
    return 0;
}

static void check_discarded_buffer(const struct trace_mapped_buffer *mapped_buffer)
{
	struct trace_records_mutable_metadata mutab;
	memcpy(&mutab, (const void *)(mapped_buffer->mapped_records->mutab), sizeof(mutab));
	const volatile struct trace_record *last_rec = &mapped_buffer->mapped_records->records[mutab.last_committed_record & mapped_buffer->mapped_records->imutab->max_records_mask];

	const bool_t buffer_was_active = (TRACE_RECORD_INVALID_COUNT != mutab.last_committed_record);
	const trace_pid_t pid = mapped_buffer->pid;
	const char *const proc_name = mapped_buffer->name;
	const trace_record_counter_t expected_next_rec = mutab.last_committed_record + 1UL;

	if (mapped_buffer->dead) {
	    if (    (expected_next_rec != mapped_buffer->mapped_records->next_flush_record)   ||
	            (expected_next_rec != mapped_buffer->mapped_records->current_read_record) ||
	            (buffer_was_active && (last_rec->ts != mutab.latest_flushed_ts))) {
	        ERR("Some records appear to have been written after the process", pid, proc_name, "had died",
	                mapped_buffer->mapped_records->next_flush_record, mapped_buffer->mapped_records->current_read_record,
	                mutab.latest_flushed_ts, last_rec->ts);
	    }
	}

	if (buffer_was_active) {
		if (! (last_rec->termination & TRACE_TERMINATION_LAST)) {
			syslog(LOG_USER|LOG_WARNING, "While discarding the buffer for %s (pid %d) found that the last record number %lu was untermintated",
					proc_name, pid, mutab.last_committed_record);
		}
	}

	trace_record_counter_t uncommitted_records = mutab.current_record - expected_next_rec;
	if (uncommitted_records > 0) {
	    WARN("The process", proc_name, pid, "has died leaving", uncommitted_records, "allocated but not committed");
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
    if (trace_munmap_if_necessary((void **)(&mapped_buffer->metadata.base_address), mapped_buffer->metadata.size) < 0) {
        REPORT_BUF_ERR("Error unmapping metadata for buffer");
    }

    if (trace_munmap_if_necessary((void **)(&mapped_buffer->records_buffer_base_address), mapped_buffer->records_buffer_size) < 0) {
        REPORT_BUF_ERR("Error unmapping records for buffer");
    }

    if (NULL != mapped_buffer->mapped_records) {
        free(mapped_buffer->mapped_records);
    }
}

/* Discard all the dumper resources the trace buffer of a process that has ended. */
void discard_buffer(struct trace_dumper_configuration_s *conf, struct trace_mapped_buffer *mapped_buffer)
{
    const pid_t pid = mapped_buffer->pid;
    INFO("Discarding pid", pid, mapped_buffer->name);
    check_discarded_buffer(mapped_buffer);

    discard_buffer_unconditionally(mapped_buffer);

    int rc = delete_shm_files(pid);
    if (0 != rc) {
        REPORT_BUF_ERR("Error deleting shm files");
    }

    if ((trace_pid_t) pid != pid) {
        WARN("Could not instruct the reader to remove resources associated with", pid, "because it can't fit in", 8*sizeof(trace_pid_t), "bits");
    }
    else if (! PidList__insertable(&conf->dead_pids)) {
        WARN("Trace dumper has too many pids pending removal, exceeding the limit of", PidList_NUM_ELEMENTS,
                ". Not enough space to insert", pid, mapped_buffer->name);
    	syslog(LOG_USER|LOG_WARNING, "Trace dumper has too many pids pending removal, exceeding the limit of %d. Not enough space to insert pid %u for process %s",
    			PidList_NUM_ELEMENTS, pid, mapped_buffer->name);
    }
    else {
        trace_pid_t tmp_pid = pid;
    	PidList__add_element(&conf->dead_pids, &tmp_pid);
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
    		removed_count,  mapped_buffer->name, pid, buffers_remaining);
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
	for (i = 0; i < mapped_buffer->n_record_buffers; i++) {
		volatile struct trace_records_mutable_metadata *const mutab =  mapped_buffer->mapped_records[i].mutab;
		const trace_record_counter_t expected_last_committed = mutab->current_record - 1;
		if (expected_last_committed != mutab->last_committed_record) {
		    WARN("Some records at the end of the trace for pid", mapped_buffer->pid, mapped_buffer->name,
		            "may be incomplete at the final flush", expected_last_committed, "!=", mutab->last_committed_record);
		}
		TRACE_ASSERT(expected_last_committed + 1 == mutab->current_record); /* Should not change, since process is dead */
		mutab->last_committed_record = expected_last_committed;
	}
}

int unmap_discarded_buffers(struct trace_dumper_configuration_s *conf)
{
    int i;
    struct trace_mapped_buffer *mapped_buffer;
    for_each_mapped_buffer(i, mapped_buffer) {
        if (!trace_process_exists(mapped_buffer->pid)) {
        	adjust_buffer_for_final_dumping(mapped_buffer);
            mapped_buffer->dead = TRUE;
        }
    }

    return 0;
}

int attach_and_map_buffers(struct trace_dumper_configuration_s *conf)
{
	if (    trace_is_initialized() &&
	        (0 == MappedBuffers__element_count(&conf->mapped_buffers)) &&
	        (0 != map_buffer(conf, getpid()))) {

        const int err = errno;
        ERR("Failed to attach to the dumper's own trace buffers", err, strerror(err));
        syslog(LOG_USER|LOG_CRIT, "Failed to attach to the dumper's own trace buffers. errno=%d - %s", err, strerror(err));
        return -1;
    }

	const int rc = map_new_buffers(conf);
	if (rc < 0) {
	    const int err = errno;
	    ERR("Failed to attach to buffers, error code =", err, strerror(err));
        syslog(LOG_USER|LOG_CRIT, "trace_dumper: Attach to buffers failed due to error %d - %s", err, strerror(err));
        return rc;
	}

	return 0;
}


bool_t has_mapped_buffers(const struct trace_dumper_configuration_s *conf)
{
    switch (MappedBuffers__element_count(&conf->mapped_buffers)) {
    case 0:
        TRACE_ASSERT(! trace_is_initialized());
        return FALSE;

    case 1: {
        struct trace_mapped_buffer *mapped_buf;
        TRACE_ASSERT(0 == MappedBuffers__get_element_ptr(&conf->mapped_buffers, 0, &mapped_buf));
        return getpid() != mapped_buf->pid;
    }

    default:
        return TRUE;
    }
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
