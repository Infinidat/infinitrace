/***
Copyright 2012 infinidat
   Written by Yitzik Casapu <yitzikc [at] infinidat.com>
   Sponsored by infinidat (http://infinidat.com)

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
***/

#ifndef __PLATFORM_H__
#define __PLATFORM_H__

#ifdef __linux__

#define _USE_INOTIFY_
#define _USE_MREMAP_
#define _USE_PROC_FS_

#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif

#define SHM_DIR "/dev/shm"

#endif

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#if defined(__APPLE_CC_) || defined(__MACH__)

#define _LARGEFILE_IS_DEFAULT_

#endif

#ifdef _LARGEFILE_IS_DEFAULT_ /* Normal Posix API functions support 64-bit files, no need for special functions */

#include <limits.h>
#ifndef ULLONG_MAX
#define ULLONG_MAX     18446744073709551615ULL
#endif

#include <unistd.h>
#define lseek64 lseek
#define ftruncate64 ftruncate
typedef off_t off64_t;

#endif


#include <errno.h>
#ifndef EFTYPE
#define EFTYPE EPROTONOSUPPORT
#endif

/* MAP_ANON is recognized on both OS/X and Linux, however it is deprecated on Linux in favor of MAP_ANONYMOUS, which is not defined on OS/X. So we do our own aliasing in case it is missing */
#include <sys/mman.h>
#ifndef MAP_ANON
#define MAP_ANON MAP_ANONYMOUS
#endif

/* Since CLANG sometimes has trouble with <emmintrin.h> we try to avoid it in traced code. Instead we call compiler intrinsics directly where we can */
#ifdef __SSE2__
#define write_int_to_ptr_uncached(__p, __v) __builtin_ia32_movnti(__p, __v);
#else
/* Fallback for platforms we don't support specifically here. This requires <emmintrin.h> to be included */
#define write_int_to_ptr_uncached(__p, __v) _mm_stream_si32(__p, __v)
#endif

#endif /* __PLATFORM_H__ */
