#ifndef __TRACE_DUMPER_FILESYSTEM_H__
#define __TRACE_DUMPER_FILESYSTEM_H__

#include "trace_dumper.h"

long long get_file_size(const char *filename);
long long total_records_in_logdir(const char *logdir);
unsigned long long calculate_free_percentage(unsigned int percent, const char *logdir);
int handle_full_filesystem(const struct trace_dumper_configuration_s *conf, const struct iovec *iov, unsigned int num_iovecs);
int delete_oldest_trace_file(const struct trace_dumper_configuration_s *conf);
int trace_create_dir_if_necessary(const char *base_dir);
int prepend_prefix_to_filename(const char *filename, const char *prefix);

#endif /* __TRACE_DUMPER_FILESYSTEM_H__ */
