/*
 * events.c:  Routines handling events that occur during the operation of the dumper.
 *
 *  Created on: Jul 3, 2013
 *  Author:          Yitzik Casapu, Infinidat
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <syslog.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <alloca.h>
#include <sys/wait.h>
#include <sysexits.h>

#include "../trace_clock.h"
#include "../trace_user.h"
#include "../min_max.h"
#include "../trace_proc_util.h"

#include "trace_dumper.h"
#include "init.h"
#include "events.h"

static int run_executable(const char *executable, const char *arg)
{
    if (access(executable, X_OK) < 0) {
        const int err = errno;
        WARN("Preliminary check before attempting to run the executable", executable, "with the argument", arg, "has failed with", err, strerror(err));
    }

    const trace_ts_t start = trace_get_nsec_monotonic();
    const pid_t pid = trace_fork();
    switch (pid) {
    case -1: {
        const int err = errno;
        ERR("Failed to run", executable, "at 1st fork due to", err, strerror(err));
        syslog(LOG_USER|LOG_ERR, "Failed to run %s at 1st fork due to error %d (%s)", executable, err, strerror(err));
        return -1;
    }

    case 0: /* Child */
         /* Now we create a second child that will perform exec(). The reason for this double fork is to leave the child process parentless so that
         * it will not become a zombie.
         * Here we use plain fork(), since we don't want to create shared-memory objects which might be overwritten if the process we exec()
         * is also traces, possibly leading to data corruption and inconsistency in the dumper.
         * We exit the intermediate child process using _exit() instead of exit(), since we want the trace buffers to be left for the parent dumper to dump.*/
        switch (fork()) {
        case -1:
            ERR("Attempt to fork second child failed with err=", errno, strerror(errno));
            _exit(trace_capped_errno());
            break;

        case 0: { /* grand-child */
            char *const argv[] = { strdupa(executable), strdupa(arg), NULL };
            TRACE_ASSERT(-1 == execvp(executable, argv));
            const int err = errno;
            syslog(LOG_USER|LOG_ERR, "Failed to exec %s in pid %d due to error %d (%s)", executable, (int) getpid(), err, strerror(err));
            if (trace_init(NULL) >= 0) {
                ERR("Failed to exec", executable, "with", arg, "due to", err, strerror(err));
            }
            else {
                syslog(LOG_USER|LOG_ERR, "Failed to initialize traces due to errno=%d (%s) after failing execvp() with errno=%d (%s)",
                        errno, strerror(errno), err, strerror(err));
            }
            _exit(EX_OSERR);
            break;
        }

        default:
            DEBUG("Intermediate child completed successfully");
            break;
        }

        _exit(0);
        break;

    default: { /* Parent */
        TRACE_ASSERT(pid > 0);
        DEBUG("Forked intermediate child with", pid);
        int status = -1;
        if (waitpid(pid, &status, 0) != pid) {
            ERR("waitpid failed for 1st child", pid, errno);
            return -1;
        }

        if (0 != status) {
            if (WIFEXITED(status)) {
                const int err = WEXITSTATUS(status);
                ERR("1st child", pid, "returned error status", err, strerror(err));
                errno = err;
            }
            else if (WIFSIGNALED(status)) {
                const int sig = WTERMSIG(status);
                ERR("1st child", pid, "returned exited with signal", sig, strsignal(sig));
                errno = EINTR;
            }
            else {
                ERR("1st child", pid, "exited inexplicably returning", status);
                errno = EPROTO;
            }

            return -1;
        }

        const trace_ts_t total_duration = trace_get_nsec_monotonic() - start;
        DEBUG("waitpid for 1st child", pid, "returned successfully.", total_duration);
        break;
    }

    }

    return 0;
}


int trace_send_event(enum trace_event evt_code, trace_event_details_t *details)
{
    const struct trace_dumper_configuration_s *const conf = trace_dumper_get_configuration();
    switch (evt_code) {
    case TRACE_FILE_CLOSED: {
        const char *const post_close_cmd = conf->post_event_actions.on_file_close;
        if (post_close_cmd) {
            return run_executable(post_close_cmd, details->filename);
        }

        break;
    }

    default:
        errno = EINVAL;
        return -1;
    }

    return 0;
}
