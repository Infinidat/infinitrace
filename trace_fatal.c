/*
 * trace_fatal.c: Utility functions for producing traces when a program experiences a fatal error.
 *
 *  Created on: Jul 15, 2013
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

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sysexits.h>
#include <assert.h>

#include "array_length.h"
#include "trace_fatal.h"
#include "trace_user.h"


int trace_log_assertion_failure(const char *file, const char *func, int line, const char *expr)
{
    FATAL("Assertion", expr, "failed at", file, line, func);
    return 0;   /* Note: returning a non-zero value here can be used to avoid exiting on the assertion. */
}

static trace_fatal_signal_custom_handler custom_fatal_sig_handler = NULL;

static void __attribute__((noreturn)) fatal_signal_handler(int sig, siginfo_t *info, void *unused __attribute__((unused)))
{
    const pid_t pid = getpid();
    const void *const fault_addr = info->si_addr;
    const int code = info->si_code;

    FATAL("Process", pid, "has received", sig, strsignal(sig), code, "at", fault_addr);

    if ((NULL != custom_fatal_sig_handler) && (custom_fatal_sig_handler(info) < 0)) {
        const int err = errno;
        ERR("Custom fatal signal handler", custom_fatal_sig_handler, "has failed with", err, strerror(err));
    }

    if ((SI_USER == code) && (pid != info->si_pid)) {
        /* The signal was sent deliberately from outside the process */
        WARN("The signal", sig, strsignal(sig), "was received from process", info->si_pid);
    }

    /* Now we re-raise the signal. Since we installed this handler with SA_NODEFER the function will not return. */
    raise(sig);

    FATAL("Failed to re-raise", sig, strsignal(sig));
    abort();
}

int trace_register_fatal_sig_handlers(trace_fatal_signal_custom_handler custom_handler)
{
    const int fatal_signals[] = { SIGABRT, SIGSEGV, SIGBUS, SIGILL, SIGFPE };

    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = fatal_signal_handler;
    act.sa_flags = SA_SIGINFO | SA_RESETHAND | SA_NODEFER;

    int rc = 0;
    for (unsigned i = 0; i < ARRAY_LENGTH(fatal_signals); i++) {
        const int sig = fatal_signals[i];
        if(sigaction(sig, &act, NULL) < 0) {
            ERR("Error registering a handler for signal", sig, strsignal(sig));
            rc = -1;
        }
    }

    if (NULL != custom_handler) {
        custom_fatal_sig_handler = custom_handler;
    }

    return rc;
}
