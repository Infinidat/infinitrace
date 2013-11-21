/*
 * trace_proc_util.c: Routines for process management and data extraction from the proc filesystem.
 *
 *  Created on: Jul 10, 2013
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

#ifndef _USE_PROC_FS_
#error "This source file makes use of procfs, which is absent on this platform."
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "halt.h"
#include "bool.h"
#include "trace_proc_util.h"
#include "trace_macros.h"


int trace_get_current_exec_basename(char *exec_name, size_t exec_name_size)
{
    char exec_path[PATH_MAX] = "";
    int rc = readlink("/proc/self/exe", exec_path, sizeof(exec_path) - 1);
    if (rc < 0) {
        return rc;
    }
    exec_path[rc] = '\0';

    exec_name[exec_name_size - 1] = '\0';
    strncpy(exec_name, basename(exec_path), exec_name_size);
    if ('\0' != exec_name[exec_name_size - 1]) {
        errno = ENAMETOOLONG;
        return -1;
    }

    return 0;
}

int trace_get_fd_path(int fd, char *file_path, size_t file_path_buf_size)
{
    char fd_proc_path[40];
    sprintf(fd_proc_path, "/proc/self/fd/%d", fd);

    const ssize_t path_len = readlink(fd_proc_path, file_path, file_path_buf_size);
    if (path_len < 0) {
        return -1;
    }

    if ((size_t) path_len >= file_path_buf_size) {
        file_path[file_path_buf_size - 1] = '\0';
        errno = ENAMETOOLONG;
        return -1;
    }

    file_path[path_len] = '\0';
    return 0;
}

static void wait_until_process_exited(pid_t pid, siginfo_t *si)
{
    siginfo_t ignored_si;
    if (NULL == si) {
        si = &ignored_si;
    }
    memset(si, 0, sizeof(*si));
    TRACE_ASSERT(0 == TEMP_FAILURE_RETRY(waitid(P_PID, pid, si, WEXITED)));
}

pid_t trace_fork_with_child_init(
        int (*child_init)(void),
        int (*cleanup_on_failure)(pid_t child_pid)
        )
{
    /* In order to guarantee that either success or failure is returned consistently in both the parent and the child we follow this procedure:
     * - The parent creates a pipe
     * - The parent forks
     * - The child calls the supplied child_init function.
     * - The child sends either 0 (if successful) or otherwise the errno value via the pipe. In case of failure it exits.
     * - If the child failed to send a completion status via the pipe or reported an error, the parent waits for it to exit.
     * */

    int pipefd[2];
    if (pipe(pipefd) < 0) {
        return -1;
    }

    int status = 0;
    const pid_t pid = fork();

    if (pid < 0) {
        status = errno;
    }
    else if (0 == pid) {    /* Child */
        if (child_init() < 0) {
            status = errno;
            TRACE_ASSERT(0 != status);
        }

        switch (write(pipefd[1], &status, sizeof(status))) {
        case sizeof(status):
            break;

        default:
            errno = EIO;
            /* no break - fall through to the regular error case */

        case -1:
            if (0 == status) {
                status = errno;
            }
            TRACE_ASSERT(0 != status);
            break;
        }

        if (0 != status) {
            cleanup_on_failure(getpid());
            _exit(MIN(status, 0xFF));
        }
    }
    else {  /* Parent */
        TRACE_ASSERT(pid > 0);
        const ssize_t n_bytes_read = read(pipefd[0], &status, sizeof(status));
        switch (n_bytes_read) {
        case sizeof(status):
            if (0 != status) {
                wait_until_process_exited(pid, NULL);
            }
            break;

        case 0: { /* The child process exited without writing a status to the pipe. */
            siginfo_t si;
            wait_until_process_exited(pid, &si);
            if (CLD_EXITED == si.si_code) {
                status = (0 != si.si_status) ? si.si_status : EIO;
            }
            else {
                cleanup_on_failure(pid);  /* The child most likely was killed by a signal, so clean after it. */
                status = EIO;
            }
            TRACE_ASSERT(0 != status);
            break;
        }

        default: /* Something went badly wrong with the pipe */
            status = (n_bytes_read < 0) ? errno : EIO;
            if (0 == kill(pid, SIGKILL)) {
                wait_until_process_exited(pid, NULL);
                cleanup_on_failure(pid);
            }
            break;
        }
    }

    close(pipefd[0]);
    close(pipefd[1]);

    if (0 != status) {
        errno = status;
        return -1;
    }

    return pid;
}

bool_t trace_process_exists(pid_t pid) {
    const int saved_errno = errno;
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
        TRACE_ASSERT(EINVAL != errno);
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

static void set_esrch_if_necessary(void)
{
    if (ENOENT == errno) {
       errno = ESRCH;
    }
}

int trace_get_process_time(pid_t pid, trace_ts_t *curtime)
{
    if (NULL == curtime) {
        errno = EFAULT;
        return -1;
    }

    struct stat stat_buf;
    int rc = stat_pid(pid, &stat_buf);
    if (0 != rc) {
        set_esrch_if_necessary();
        return -1;
    }

    *curtime = stat_buf.st_ctim.tv_sec * TRACE_SECOND + stat_buf.st_ctim.tv_nsec;
    return 0;
}


static pid_t get_proc_ppid(pid_t pid)
{
    char name[NAME_MAX + 10];
    TRACE_ASSERT(sprintf(name, "/proc/%d/stat", (int) pid) > 0);

    FILE *const fp = fopen(name, "rt");
    if (NULL == fp) {
        set_esrch_if_necessary();
        return -1;
    }

    static const char fmt[] = "%d %s %c %d";
    pid_t reported_pid = -1, ppid = -1;
    char state;

    if ((fscanf(fp, fmt, &reported_pid, name, &state, &ppid) != 4) ||
        (reported_pid != pid)) {
        errno = EPROTO;
        ppid = -1;
    }

    fclose(fp);
    return ppid;
}


bool_t trace_is_process_descended_from_pids(pid_t pid, const pid_t potential_parents[], size_t n_potential_parents)
{
    const pid_t ppid = get_proc_ppid(pid);
    if (ppid < 0) {
       return FALSE;
    }

    size_t i;
    for (i = 0; i < n_potential_parents; i++) {
        if (potential_parents[i] == ppid) {
            return TRUE;
        }
    }

    if (ppid <= 1) {  /* init process */
        return FALSE;
    }

    return trace_is_process_descended_from_pids(ppid, potential_parents, n_potential_parents);
}
