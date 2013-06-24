/*
 *  trace_mmap_util.c
 *  Routines for working with memory mappings
 *
 *  Created on: Oct 20, 2013
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

#include "platform.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <string.h>

#include "trace_macros.h"
#include "trace_mmap_util.h"

void *trace_mmap_private_anon_mem(size_t size)
{
    return mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
}

void *trace_mmap_grow(void *const addr, size_t size, size_t new_size)
{
 #ifdef _USE_MREMAP_
    if (NULL == addr) {
        if (0 != size) {
            errno = EINVAL;
            return MAP_FAILED;
        }
        return trace_mmap_private_anon_mem(new_size);
    }
    return mremap(addr, size, new_size, MREMAP_MAYMOVE);
#else
    void* new_addr = trace_mmap_private_anon_mem(new_size);
    if ((new_addr != MAP_FAILED) && (addr)) {
        memcpy(new_addr, addr, size);
        munmap(addr, size);
    }

    return new_addr;

#endif
}

#define IS_POWER_OF_2(x) (((0 != (x)) && (0 == ((x) & ((x) - 1)))))

size_t trace_get_page_size()
{
    static long long page_size = 0;

    if (!page_size) {
        page_size = sysconf(_SC_PAGE_SIZE);
        if (!IS_POWER_OF_2(page_size)) {
            page_size = 4096;
        }
    }

    return page_size;
}

size_t trace_round_size_up_to_multiple(size_t size, size_t multiple)
{
    TRACE_ASSERT(IS_POWER_OF_2(multiple));
    return (size + multiple - 1) & ~(multiple - 1);
}

size_t trace_round_size_up_to_page_size(size_t size)
{
    return trace_round_size_up_to_multiple(size, trace_get_page_size());
}

int trace_munmap_if_necessary(void **mapping_base, size_t len)
{
    if (NULL == mapping_base) {
        errno = EFAULT;
        return -1;
    }

    void *const addr = *mapping_base;
    if (MAP_FAILED != addr) {
        *mapping_base = MAP_FAILED;
        if (munmap(addr, len) != 0) {
            *mapping_base = addr;
            return -1;
        }
    }

    return 0;
}
