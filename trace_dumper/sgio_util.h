/*
 * sgio_util.h
 * Routines for using scatter-gather I/O (e.g. writev()) and its data structures
 *
 *  Created on: Oct 17, 2013
 *  Author:     Yitzik Casapu, Infinidat
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

#ifndef SGIO_UTIL_H_
#define SGIO_UTIL_H_

#include <sys/uio.h>

size_t total_iovec_len(const struct iovec *iov, int iovcnt);
int max_iovecs_fitting_size(const struct iovec *iov, int iovcnt, size_t max_size);
ssize_t copy_iov_to_buffer(void *buffer, const struct iovec *iov, int iovcnt);
ssize_t trace_dumper_writev(int fd, const struct iovec *iov, int iovcnt);

struct trace_record;
static inline struct trace_record *trace_record_from_iov(const struct iovec *iov) { return (struct trace_record *) (iov->iov_base); }

#endif /* SGIO_UTIL_H_ */
