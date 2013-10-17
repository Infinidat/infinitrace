/*
 * sgio_util.c
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

#include "../platform.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>

#include "../min_max.h"
#include "../trace_macros.h"
#include "sgio_util.h"

size_t total_iovec_len(const struct iovec *iov, int iovcnt)
{
    size_t total = 0;
    int i;
    for (i = 0; i < iovcnt; i++) {
        total += iov[i].iov_len;
    }

    return total;
}

ssize_t copy_iov_to_buffer(void *buffer, const struct iovec *iov, int iovcnt)
{
    if ((NULL == iov) || (NULL == buffer)) {
        errno = EFAULT;
        return -1;
    }

    if (iovcnt < 0) {
        errno = EINVAL;
        return -1;
    }

    void *target = buffer;
    for (int i = 0; i < iovcnt; i++) {
        if (NULL == iov[i].iov_base) {
            errno = EFAULT;
            return -1;
        }
        target = mempcpy(target, iov[i].iov_base, iov[i].iov_len);
    }

    return (const char *)target - (const char *)buffer;
}

ssize_t trace_dumper_writev(int fd, const struct iovec *iov, int iovcnt)
{
    ssize_t length = total_iovec_len(iov, iovcnt);
    void *buffer = malloc(length);
    if (NULL == buffer) {
        return -1;
    }

    TRACE_ASSERT(copy_iov_to_buffer(buffer, iov, iovcnt) == length);

    ssize_t bytes_written = TEMP_FAILURE_RETRY(write(fd, buffer, length));
    free(buffer);
    return bytes_written;
}
