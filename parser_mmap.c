/*
 * parser_mmap.c
 *
 *
 * Routines for creating and applying memory mappings of file data - either directly to binary files or to temporary
 * anonymous memory mappings containing data extraced via zlib.
 *
 *  Created on:   Jan 14, 2013 by Yitzik Casapu, Infinidat
 *  Copyright by  Infinidat (http://infinidat.com)
 *  Contributors: Josef Ezra, Yitzik Casapu and others of Infinidat
 *                Yotam Rubin
 *  Maintainer:   Yitzik Casapu, Infinidat
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <errno.h>
#include <assert.h>
#include <zlib.h>

#ifdef _USE_INOTIFY_
#include <sys/inotify.h>
#endif

#include "trace_mmap_util.h"
#include "min_max.h"
#include "parser.h"
#include "parser_mmap.h"

/* Remove rlimits for virtual memory, which could prevent trace_reader from running */
static int remove_limits(void)
{
    const struct rlimit limit = { RLIM_INFINITY, RLIM_INFINITY };
    return setrlimit(RLIMIT_AS, &limit);
}

static unsigned long long ull_from_le_bytes(const unsigned char *bytes, size_t len)
{
    unsigned long long result = 0;
    assert(len <= sizeof(result));
    for (size_t i = 0; i < len; i++) {
        result += ((unsigned) bytes[i]) << 8*i;
    }

    return result;
}

/* Attempt to treat the file as a gzip archive and extract its content into a mn anonymously mapped memory are.
 * Return values:
 *  NULL - If the file is not a gzip archive.
 *  MAP_FAILED - If the file appears to be a gzip archive, but cannot be mapped, or does not seem to be a normal file.
 *  */
static void *mmap_gzip(int fd, off64_t *input_size)
{
    int new_fd = -1;
    gzFile gz;
    enum field_sizes { gz_size_len = 4 };   /* unfortunately gzip's size field is 32-bit, so larger file sizes can't be specified directly */
    unsigned char u[gz_size_len];
    void *addr = MAP_FAILED;
    off64_t size = -1;
    int len = -1;
    off64_t offset = 0;
    off64_t avail = 0;


    if ((lseek64(fd, -gz_size_len, SEEK_END) == (off64_t) -1) || (read(fd, u, sizeof(u)) != gz_size_len)) {
        /* This can legitimately fail for a file whose size is currently 0 (but might grow), so we return NULL */
        return NULL;
    }


    size = ull_from_le_bytes(u, gz_size_len);

    if (size < *input_size) {
        size = (double)*input_size * 1.3;
    }

    if (lseek64(fd, 0, SEEK_SET) != 0) {
        return MAP_FAILED;
    }

    new_fd = dup(fd);
    if (new_fd < 0) {
        return MAP_FAILED;
    }

    gz = gzdopen(new_fd, "rb");
    if (gz == NULL) {
        close(new_fd);
        return NULL;
    }
    new_fd = -1;

    if (gzdirect(gz)) {
        gzclose(gz);
        return NULL;
    }

    size = trace_round_size_up_to_page_size(size);

    addr = trace_mmap_grow(NULL, 0, size);
    if (addr == MAP_FAILED) {
        gzclose(gz);
        return addr;
    }

    for (avail = size;;) {
#define CHUNK 65536
        len = gzread(gz, (char*)addr + offset, MIN(CHUNK, avail));
        if (len < 0) {
            gzclose(gz);
            munmap(addr, size);
            return MAP_FAILED;
        }
        if (len == 0) {
            break;
        }
        offset += len;
        avail -= len;

        // size in trailer doesn't match actual data - more than 4G of input?
        if (avail == 0) {
            long long new_size = trace_round_size_up_to_page_size(size + 0x100000000ll);
            void* new_addr;

            remove_limits();

            new_addr = trace_mmap_grow(addr, size, new_size);

            if (addr == MAP_FAILED) {
                gzclose(gz);
                munmap(addr, size);
                return MAP_FAILED;
            }

            avail = new_size - size;
            addr = new_addr;
            size = new_size;
        }
    }

    gzclose(gz);

    *input_size = offset;

    return addr;
}

static void *mmap_fd(int fd, off64_t *size)
{
    void *const addr = mmap_gzip(fd, size);
    assert(MAP_FAILED != NULL);

    if (addr != NULL) {
        return addr;
    }

    return mmap(NULL, *size, PROT_READ, MAP_SHARED, fd, 0);
}

static off64_t get_current_end_offset_from_fd(int fd, bool_t minimum_size)
{
    struct stat st;
    if (0 != fstat(fd, &st)) {
        return (off64_t) -1;
    }

    if (minimum_size) {
        const off64_t allocated_size = (off64_t) S_BLKSIZE * st.st_blocks;
        return MIN(allocated_size, st.st_size);
    }
    else {
        return st.st_size;
    }

}

int trace_parser_mmap_file(struct trace_parser *parser, const char *filename)
{
    off64_t size = -1;
    void *addr = MAP_FAILED;

    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    size = get_current_end_offset_from_fd(fd, parser->wait_for_input);
    if (size < 0) {
        goto failure_cleanup;
    }

    addr = mmap_fd(fd, &size);
    if ((MAP_FAILED == addr) && (ENOMEM == errno)) {
        /* The failure may be due to rlimit for virtual memory set too low, so try to raise it */
        if (0 != remove_limits()) {
            goto failure_cleanup;
        }
        addr = mmap_fd(fd, &size);
    }

    if (MAP_FAILED == addr) {
        goto failure_cleanup;
    }

    assert(-1 == parser->file_info.fd);
    parser->file_info.fd = fd;

    assert(MAP_FAILED == parser->file_info.file_base);
    parser->file_info.file_base = addr;

    parser->file_info.end_offset = size;
    parser->file_info.current_offset = 0;
    return 0;

failure_cleanup:
    close(fd);
    return -1;
}

void trace_parser_unmap_file(struct trace_parser *parser)
{
    if (MAP_FAILED != parser->file_info.file_base) {
        assert(0 == munmap(parser->file_info.file_base, parser->file_info.end_offset));
        parser->file_info.file_base = MAP_FAILED;
    }

    parser->file_info.end_offset = 0;

#ifdef _USE_INOTIFY_
    if (-1 != parser->inotify_descriptor) {
        assert(0 == inotify_rm_watch(parser->inotify_fd, parser->inotify_descriptor));
        parser->inotify_descriptor = -1;
    }

    if (-1 != parser->inotify_fd) {
        assert(0 == close(parser->inotify_fd));
        parser->inotify_fd = -1;
    }
#endif

    if (-1 != parser->file_info.fd) {
        assert(0 == close(parser->file_info.fd));
        parser->file_info.fd = -1;
    }
}


static void *resize_mapping(struct trace_parser *parser, off64_t new_end)
{
#ifdef _USE_MREMAP_

    return mremap(parser->file_info.file_base, parser->file_info.end_offset, new_end, MREMAP_MAYMOVE);

#else

    if (0 != munmap(parser->file_info.file_base, parser->file_info.end_offset)) {
        return MAP_FAILED;
    }
    return mmap(NULL, new_end, PROT_READ, MAP_SHARED, parser->file_info.fd, 0);

#endif
}

off64_t trace_parser_update_end_offset(struct trace_parser *parser)
{
    const off64_t new_end = get_current_end_offset_from_fd(parser->file_info.fd, FALSE);
    if (new_end != parser->file_info.end_offset) {
        assert(new_end > parser->file_info.end_offset);
        void *const new_addr = resize_mapping(parser, new_end);
        if (!new_addr || MAP_FAILED == new_addr) {
            return -1;
        }

        parser->file_info.end_offset = new_end;
        parser->file_info.file_base = new_addr;
    }

    return new_end;
}
