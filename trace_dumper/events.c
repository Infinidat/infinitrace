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

#include "trace_dumper.h"
#include "init.h"
#include "events.h"

/* Cap the value of errno to guarantee it can be passed in the exit status value without being truncated to 0 */
static int capped_errno()
{
    return MIN(errno, 0xFF);
}

static int run_executable(const char *executable, const char *arg)
{
    if (access(executable, X_OK) < 0) {
        const int err = errno;
        WARN("Preliminary check before attempting to run the executable", executable, "with the argument", arg, "has failed with", err, strerror(err));
    }

    const trace_ts_t start = trace_get_nsec_monotonic();
    const pid_t pid = fork();
    switch (pid) {
    case -1: {
        const int err = errno;
        ERR("Failed to run", executable, "at 1st fork due to", err, strerror(err));
        syslog(LOG_USER|LOG_ERR, "Failed to run %s at 1st fork due to error %d (%s)", executable, err, strerror(err));
        return -1;
    }

    case 0: { /* Child */
        switch (fork()) {
        case -1:
            exit(capped_errno());

        case 0: { /* grand-child */
            char *const argv[] = { strdupa(executable), strdupa(arg), NULL };
            assert(-1 == execvp(executable, argv));
            syslog(LOG_USER|LOG_ERR, "Failed to exec %s in pid %d due to error %d (%s)", executable, (int) getpid(), errno, strerror(errno));
            exit(EX_OSERR);
            break;
        }

        default:
            exit(0);
        }

        break;
    }

    default: { /* Parent */
        assert(pid > 0);
        DEBUG("Forked intermediate child with", pid);
        int status = -1;
        if (waitpid(pid, &status, 0) != pid) {
            ERR("waitpid failed for 1st child", pid);
            return -1;
        }

        if (0 != status) {
            ERR("1st child", pid, "returned error status", status, strerror(status));
            errno = status;
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
