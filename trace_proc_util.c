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

    const ssize_t path_len = readlink(file_path, file_path, file_path_buf_size);
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


static int reset_sigchld_to_dfl(struct sigaction *old_sigchld_act)
{
    struct sigaction sigchld_act;
    memset(&sigchld_act, 0, sizeof(sigchld_act));
    sigchld_act.sa_handler = SIG_DFL;
    sigchld_act.sa_flags   = SA_RESTART;
    return sigaction(SIGCHLD, &sigchld_act, old_sigchld_act);
}

static int restore_sigchld(const struct sigaction *old_sigchld_act)
{
    return sigaction(SIGCHLD, old_sigchld_act, NULL);
}

pid_t trace_fork_with_child_init(
        int (*child_init)(void),
        int (*cleanup_on_failure)(pid_t child_pid)
        )
{

    /* In order to guarantee that either success or failure is returned consistently in both the parent and the child we follow this procedure:
     * - The parent forks
     * - The child creates the shared-memory areas. If it fails it exits, using the exit value to communicate errno.
     * - The child suspends itself using SIGSTOP
     * - The parent waits until the child has either stopped itself with SIGSTOP or exited.
     * - The parent resumes the child with SIGCONT, and waits for it to receive SIGCONT.
     * */

    /* In case the parent process was playing funny tricks with SIGCHLD, try to disable them temporarily. */
    struct sigaction old_sigchld_act;
    if (0 != reset_sigchld_to_dfl(&old_sigchld_act)) {
        return -1;
    }

    pid_t pid = fork();

    if (0 == pid) {    /* Child */
        if (    (child_init() < 0)                       ||
                (restore_sigchld(&old_sigchld_act) != 0) ||
                (raise(SIGSTOP) != 0)      ) {
            TRACE_ASSERT(0 != errno);
            const int err = trace_capped_errno();
            cleanup_on_failure(getpid());
            _exit(err);
        }

        return 0;
    }
    else if (pid > 0) {  /* Parent */

        siginfo_t si;
        memset(&si, 0, sizeof(si));

        /* Make sure that the child has stopped and then deliver SIGCONT to wake it up. */
        TRACE_ASSERT(0 == TEMP_FAILURE_RETRY(waitid(P_PID, pid, &si, WSTOPPED | WEXITED)));
        TRACE_ASSERT(pid == si.si_pid);
        if (CLD_STOPPED != si.si_code) {    /* The child encountered an error and exited */
            /* If the child exited normally, propagate the code it conveyed via its exit status to errno. Otherwise use generic EIO. */
            if (CLD_EXITED == si.si_code) {
                errno = (0 != si.si_status) ? si.si_status : EIO;
            }
            else {
                cleanup_on_failure(pid);  /* The child most likely was killed by a signal, so clean after it. */
                errno = EIO;
            }
            pid = -1;
        }
        else if (pid == si.si_pid) {  /* The child has completed its initialization and stopped, and is waiting for us to sent it SIGCONT */
            TRACE_ASSERT(SIGSTOP == si.si_status);
            if (0 == kill(pid, SIGCONT)) {
                /* Wait for the child to continue, so that if user-code in the parent process waits for it to continue it will not
                 * return prematurely */
                memset(&si, 0, sizeof(si));
                TRACE_ASSERT(0 == TEMP_FAILURE_RETRY(waitid(P_PID, pid, &si, WCONTINUED)));
                TRACE_ASSERT(CLD_CONTINUED == si.si_code);
            }
            else {
                if (ESRCH == errno) {  /* Process gone */
                    cleanup_on_failure(pid);
                }
                pid = -1;
            }
        }
        else {  /* Someone else has stopped our child, e.g. by using pkill / killall on our process name */
            if (0 == kill(pid, SIGKILL)) {
                TRACE_ASSERT(0 == TEMP_FAILURE_RETRY(waitid(P_PID, pid, &si, WEXITED)));
                cleanup_on_failure(pid);
            }
            errno = EINTR;
            pid = -1;
        }
    }

    TRACE_ASSERT(0 == restore_sigchld(&old_sigchld_act));
    return pid;
}
