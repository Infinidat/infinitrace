/*
 * init.c
 *
 *  Created on: Aug 8, 2012
 *      Original Author: Yotam Rubin
 *      Maintainer:		 Yitzik Casapu, Infinidat
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <sysexits.h>
#include <syslog.h>
#include <errno.h>
#include <limits.h>

#include "../trace_user.h"
#include "../opt_util.h"
#include "../trace_str_util.h"
#include "../trace_clock.h"
#include "../trace_fatal.h"
#include "trace_dumper.h"
#include "filesystem.h"
#include "buffers.h"
#include "init.h"
#include "open_close.h"
#include "internal_buffer.h"
#include "mm_writer.h"

static struct trace_dumper_configuration_s trace_dumper_configuration;

static const char usage[] = {
    "Usage: %s [params]                                                                                            \n" \
    "                                                                                                              \n" \
    " -h, --help                            Display this help message                                              \n" \
    " -f  --filter [buffer_name]            Filter out specified buffer name                                       \n" \
    " -n  --no-color                        Show online data without color                                         \n" \
    " -w  --write-to-file[filename]         Write log records to file                                              \n" \
    " -l  --low-latency-write[param=value]  Write to files in low-latency mode (which uses mmap), optionally specifying a parameter \n"
    "                                       This option may recur multiple times with different parameters. Recognized parameters: \n" \
    "                                           max_recs_pending:       Maximum number of records which haven't been confirmed to be committed to disk \n" \
    "                                           write_size_bytes:       The dumper should attempt to write n byte blocks aligned to n byte boundaries \n" \
    "                                           max_flush_interval_ms:  Maximum interval between flushes to disk (assuming there is data to be written) \n" \
    " -c  --compressed[param=value]         Write to files in a compressed format using a memory buffer, optionally specifying a parameter \n" \
    "                                       This option may recur multiple times with different parameters. Recognized parameters: \n" \
    "                                           buffer size:            Buffer size in bytes (will be rounded to pages) \n" \
    " -N  --notification-file[filename]     Write notifications (messages with severity > notification level) to a separate file\n" \
    " -L  --notification-level[level]       Specify minimum severity that will be written to the notification file (default: WARN)\n" \
    " -b  --logdir                          Specify the base log directory trace files are written to              \n" \
    " -p  --pid [pid]                       Attach the specified process and its descendants                       \n" \
    " -q  --quota-size [bytes/percent]      Specify the total number of bytes that may be taken up by trace files  \n" \
    " -r  --record-write-limit [records]    Specify maximal amount of records that can be written per-second (unlimited if not specified)  \n" \
    " -I  --instrument[option]              Turn on one of the dumper's instrumentation options. Available option values: time_writes \n"     \
    " -E  --execute-on-event[evant=path]    Run the executable at 'path' when 'event' occurs. Supported events:\n"     \
    "                                            file_closed:           An output file, whose name is supplied to the executable as argument, was closed." \
    " -v  --dump-online-statistics          Dump buffer statistics \n"
    "\n"};

static const struct option longopts[] = {
    { "help", 0, 0, 'h'},
	{ "filter", required_argument, 0, 'f'},
    { "logdir", required_argument, 0, 'b'},
	{ "no-color", 0, 0, 'n'},
    { "pid", required_argument, 0, 'p'},
    { "write-to-file", optional_argument, 0, 'w'},
    { "low-latency-write", optional_argument, 0, 'l'},
    { "compressed", optional_argument, 0, 'c'},
    { "notification-file",  optional_argument, 0, 'N'},
    { "notification-level", required_argument, 0, 'L'},
    { "quota-size", required_argument, 0, 'q'},
    { "record-write-limit", required_argument, 0, 'r'},
    { "instrument", required_argument, 0, 'I'},
    { "execute-on-event", required_argument, 0, 'E'},
    { "dump-online-statistics", 0, 0, 'v'},

	{ 0, 0, 0, 0}
};

void print_usage(const char *prog_name)
{
	const char *display_name = (NULL == prog_name) ? "trace_dumper" : prog_name;
    printf(usage, display_name);
}


#define DEFAULT_LOG_DIRECTORY "/mnt/logs/traces"

static void init_compiled_in_defaults(struct trace_dumper_configuration_s *conf)
{
    memset(conf, 0, sizeof(*conf));

    /* TODO: Make the following parameters configurable at runtime. */
    conf->notifications_subdir = "warn";
    conf->log_details = FALSE;
    conf->buffered_mode_flush_max_interval = TRACE_MS * 50;

    /* Compiled-in defaults, can be overridden via the command-line */
    conf->max_records_pending_write_via_mmap = ULONG_MAX;
    conf->max_flush_interval = 1 * TRACE_SECOND;
    conf->preferred_flush_bytes = 0; /* Use page size */
    conf->attach_to_pid = 0;
    conf->compression_algo = 0;     /* disabled */
    conf->internal_buf_size = 2 << 26;
}

static bool_t param_eq(const char *user_given_name, const char *param_name)
{
    return 0 == strcasecmp(user_given_name, param_name);
}

static int parse_low_latency_mode_param(struct trace_dumper_configuration_s *conf, const char *arg)
{
    char *name = NULL;
    char *str_value = NULL;

    if (arg && *arg) {
        long long value = -1;
        const bool_t is_num = trace_parse_name_value_pair(strdupa(arg), &name, &str_value, &value);
        if (! is_num) {
            fprintf(stderr, "The value %s specified for low-latency mode parameter %s is not valid number\n", str_value, name);
            goto return_einval;
        }

        if (param_eq(name, "max_recs_pending")) {
            if (value > 0)
                conf->max_records_pending_write_via_mmap = value;
            else
                goto num_out_of_range;
        } else if (param_eq(name, "write_size_bytes")) {
            if (value >= 0)
                conf->preferred_flush_bytes = value;
            else
                goto num_out_of_range;
        } else if (param_eq(name, "max_flush_interval_ms")) {
            if (value >= 0)
                conf->max_flush_interval = TRACE_MS * value;
            else
                goto num_out_of_range;
        } else {
            fprintf(stderr, "Unknown low-latency mode parameter %s\n", name);
            goto return_einval;
        }
    }

    return 0;

num_out_of_range:
    fprintf(stderr, "The value %s specified for %s is outside the permitted range\n", str_value, name);
return_einval:
    errno = EINVAL;
    return -1;
}

static int parse_compressed_mode_param(struct trace_dumper_configuration_s *conf, const char *arg)
{
    char *name = NULL;
    char *str_value = NULL;

    if (0 == conf->compression_algo) {
        conf->compression_algo = TRACE_CHUNK_HEADER_FLAG_COMPRESSED_SNAPPY;
    }

    if (arg && *arg) {
        long long value = -1;
        const bool_t is_num = trace_parse_name_value_pair(strdupa(arg), &name, &str_value, &value);
        if (! is_num) {
            fprintf(stderr, "The value %s specified for compressed mode parameter %s is not valid number\n", str_value, name);
            goto return_einval;
        }

        if (param_eq(name, "max_recs_pending")) {
            if (value > 0)
                conf->internal_buf_size = value;
            else
                goto num_out_of_range;
        }
        else {
            fprintf(stderr, "Unknown compressed mode parameter %s\n", name);
            goto return_einval;
        }
    }

    return 0;

    num_out_of_range:
        fprintf(stderr, "The value %s specified for %s is outside the permitted range\n", str_value, name);
    return_einval:
        errno = EINVAL;
        return -1;
}

static int parse_execute_on_event_param(struct trace_dumper_configuration_s *conf, const char *arg)
{
    char *name = NULL;
    char *str_value = NULL;

    if (arg && *arg) {
        char *const tmp_arg = strdupa(arg);
        trace_parse_name_value_pair(tmp_arg, &name, &str_value, NULL);
        if (! *str_value) {
            goto invalid_format;
        }

        const char *const value_non_volatile = arg + (str_value - tmp_arg);

        if (param_eq(name, "file_closed")) {
            conf->post_event_actions.on_file_close = value_non_volatile;
        } else {
            fprintf(stderr, "Unknown low-latency mode parameter %s\n", name);
            goto return_einval;
        }
    }
    else {
        goto invalid_format;
    }

    return 0;

invalid_format:
    fprintf(stderr, "execute-on-event option requires an argument in the format event=path_to_executable\n");
return_einval:
    errno = EINVAL;
    return -1;
}

static pid_t get_pid_from_optarg(void)
{
    long long pid;
    if (trace_get_number(optarg, &pid) && (pid > 0)) {
        return (pid_t) pid;
    }

    errno = EINVAL;
    return -1;
}

int parse_commandline(struct trace_dumper_configuration_s *conf, int argc, char **argv)
{
    char shortopts[MAX_SHORT_OPTS_LEN(ARRAY_LENGTH(longopts))];
    short_opts_from_long_opts(shortopts, longopts);
    init_compiled_in_defaults(conf);

    int o = 0;
    while ((o = getopt_long(argc, argv, shortopts, longopts, 0)) != EOF) {
		switch (o) {
		case 'h':
			break;
		case 'f':
			add_buffer_filter(conf, optarg);
			break;
        case 'b':
            conf->logs_base = optarg;
            break;
        case 'n':
            conf->no_color_specified = 0;
            break;
        case 'p':
            conf->attach_to_pid = get_pid_from_optarg();
            if (conf->attach_to_pid <= 0) {
                fprintf(stderr, "Invalid process-id to attach specified: %s\n", optarg);
                return -1;
            }
            INFO("Trace dumper will attach to pid", conf->attach_to_pid);
            break;
        case 'w':
            conf->write_to_file = 1;
            conf->fixed_output_filename = optarg;
            break;
        case 'l':
        	conf->low_latency_write = TRUE;
        	if (parse_low_latency_mode_param(conf, optarg) < 0) {
        		fprintf(stderr, "Bad low-latency parameter specification %s\n", optarg);
        		return -1;
        	}
        	break;
        case 'c':
            if (parse_compressed_mode_param(conf, optarg) < 0) {
                fprintf(stderr, "Bad compressed parameter specification %s\n", optarg);
                return -1;
            }
            break;
        case 'N':
            conf->write_notifications_to_file = 1;
            conf->fixed_notification_filename = optarg;
            break;
        case 'L':
        	conf->minimal_notification_severity = trace_str_to_severity_case_insensitive(optarg);
        	if (TRACE_SEV_INVALID == conf->minimal_notification_severity) {
        		fprintf(stderr, "Invalid trace level specified: %s", optarg);
        		return -1;
        	}
        	break;
        case 'q':
            conf->quota_specification = optarg;
            break;
        case 'r':
            conf->max_records_per_second = atoi(optarg);
            break;
        case 'I':
        	if (param_eq(optarg, "time_writes")) {
        		conf->log_performance_to_file = 1;
        	}
        	else {
        		fprintf(stderr, "Unrecognized trace dumper instrumentation option: %s\n", optarg);
        		return -1;
        	}
        	break;
        case 'E':
            if (parse_execute_on_event_param(conf, optarg) < 0) {
                fprintf(stderr, "Bad execute-on-event specification %s\n", optarg);
                return -1;
            }
            break;
        case 'v':
            conf->dump_online_statistics = 1;
            break;
        case '?':
        default:
            fprintf(stderr, "Uncrecognized command-line option: %c\n", o);
            return -1;
        }
    }

    return 0;
}

#define ROTATION_COUNT 10
static const trace_ts_t FLUSH_DELTA = 5000;  /* In ns */

static unsigned long long parse_quota_specification(const char *quota_specification, const char *logdir)
{
    unsigned long long max_bytes;
    if (quota_specification[0] == '%') {
        max_bytes = calculate_free_percentage(atoi(&quota_specification[1]), logdir);
    } else {
        max_bytes = atoll(quota_specification);
    }

    if (0 == max_bytes) { /* The user has explicitly disabled quota management */
    	max_bytes = LLONG_MAX;
    }
    else {
    	max_bytes /= sizeof(struct trace_record);
    }

    return max_bytes;
}


static int set_quota(struct trace_dumper_configuration_s *conf)
{
    if (conf->quota_specification) {
        conf->max_records_per_logdir = parse_quota_specification(conf->quota_specification, conf->logs_base);
        if (conf->max_records_per_logdir == 0) {
            return -1;
        }

        if (conf->max_records_per_logdir < TRACE_PREFERRED_FILE_MAX_RECORDS_PER_FILE) {
            conf->max_records_per_file = conf->max_records_per_logdir / PREFERRED_NUMBER_OF_TRACE_HISTORY_FILES;
        } else {
            conf->max_records_per_file = TRACE_PREFERRED_FILE_MAX_RECORDS_PER_FILE;
        }
    } else {
        conf->max_records_per_file = TRACE_PREFERRED_FILE_MAX_RECORDS_PER_FILE;
        conf->max_records_per_logdir = TRACE_PREFERRED_MAX_RECORDS_PER_LOGDIR;
    }

    if (trace_quota_is_enabled(conf)) {
    	syslog(LOG_USER|LOG_INFO, "Trace dumper quota is set to %lld records per log directory, in %lu record files",
    			conf->max_records_per_logdir, conf->max_records_per_file);
    }

    return 0;
}

static int init_record_file(struct trace_record_file *record_file, size_t initial_iov_len)
{
	record_file->fd = -1;
	record_file->filename[0] = '\0';
	record_file->records_written = 0;
	record_file->mapping_info = NULL;
	record_file->post_write_validator = NULL;
	record_file->validator_context = NULL;
	record_file->perf_log_file = NULL;
	record_file->iov_allocated_len = (initial_iov_len > 0U) ? initial_iov_len : (size_t) sysconf(_SC_IOV_MAX);
	record_file->iov = calloc(record_file->iov_allocated_len, sizeof(struct iovec));
	if (NULL == record_file->iov) {
		return -1;
	}
	return 0;
}

/* The dumper cannot assume that another process will clean-up its shared-memory objects, so we have to do this explicitly */
static void set_trace_cleanup_for_dumper(void)
{
#ifdef __TRACE_INSTRUMENTATION
    TRACE_ASSERT(0 == atexit(TRACE__fini));
#endif
}

int init_dumper(struct trace_dumper_configuration_s *conf)
{
    set_trace_cleanup_for_dumper();
    clear_mapped_records(conf);

    if (!conf->write_to_file && conf->dump_online_statistics) {
        conf->op_type = OPERATION_TYPE_DUMP_BUFFER_STATS;
    } else {
        conf->op_type = OPERATION_TYPE_DUMP_RECORDS;
    }

    if (! conf->logs_base) {
    	conf->logs_base = DEFAULT_LOG_DIRECTORY;
    }

    if ((! conf->fixed_output_filename) && (trace_create_dir_if_necessary(conf->logs_base) != 0)) {
        return EX_CANTCREAT;
    }

    conf->record_file.fd = -1;
    if (conf->write_notifications_to_file && init_record_file(&conf->notification_file, 0) != 0) {
    	return EX_SOFTWARE;
    }

    conf->ts_flush_delta = FLUSH_DELTA;
    conf->next_housekeeping_ts = 0;


    if (conf->syslog) {
        openlog("traces", 0, 0);
    }

    if (conf->minimal_notification_severity < TRACE_SEV__MIN) {
    	conf->minimal_notification_severity = TRACE_SEV_WARN;
    }

    if (set_quota(conf) != 0) {
        return EX_IOERR;
    }

    if (conf->low_latency_write) {
    	INFO("Trace dumper is writing records in low latency mode using memory mappings, with max_recs_pending=", conf->max_records_pending_write_via_mmap,
    	        "write_size_bytes= ", conf->preferred_flush_bytes, "max_flush_interval_ms=", conf->max_flush_interval);
    }
    else if (conf->compression_algo) {
        /* Check that exactly one compression algorithm is enabled */
        TRACE_ASSERT((  (TRACE_CHUNK_HEADER_FLAG_COMPRESSED_ANY & conf->compression_algo) == conf->compression_algo) &&
                        (1 == __builtin_popcount(conf->compression_algo)));
        TRACE_ASSERT(conf->internal_buf_size > 0);
        conf->record_file.internal_buf = internal_buf_alloc(conf->internal_buf_size);
        INFO("Allocated internal buffer of nominal size", conf->internal_buf_size, "bytes, n_recs=", conf->record_file.internal_buf->n_recs);
    }

    return 0;
}

struct trace_dumper_configuration_s *trace_dumper_get_configuration()
{
	return &trace_dumper_configuration;
}


/* Signal handling */

static void normal_termination_handler(int sig, siginfo_t *info, void *params __attribute__((unused)))
{
	syslog(LOG_USER|LOG_INFO, "Trace dumper has received signal %d (%s) from pid %d and will exit", sig, strsignal(sig), info->si_pid);
	trace_dumper_configuration.stopping = TRUE;
	request_file_operations(&trace_dumper_configuration, TRACE_REQ_CLOSE_ALL_FILES | TRACE_REQ_DISCARD_ALL_BUFFERS);
}

static void sigusr_handler(int sig, siginfo_t *info __attribute__((unused)), void *params __attribute__((unused)))
{
	unsigned op_flags = TRACE_REQ_CLOSE_ALL_FILES;
	switch(sig) {
	case SIGUSR1:
		break;

	case SIGUSR2:
		op_flags |= TRACE_REQ_RENAME_ALL_FILES;
		break;

	default:
		TRACE_ASSERT(0);
		return;
	}

	request_file_operations(&trace_dumper_configuration, op_flags);
}

int set_signal_handling(void)
{
	int rc = trace_register_fatal_sig_handlers(NULL);
	const int default_flags = SA_SIGINFO|SA_RESTART;

	const struct {
		int sig;
		void (*handler)(int, siginfo_t *, void *);
		int override_flags;
	} sig_handlers[] = {
		{ SIGUSR1, sigusr_handler, 0 },
		{ SIGUSR2, sigusr_handler, 0 },
		{ SIGTERM, normal_termination_handler, 0 },
	};

	unsigned i;
	for (i = 0; i < ARRAY_LENGTH(sig_handlers); i++) {
		struct sigaction act;
		memset(&act, 0, sizeof(act));
		act.sa_sigaction = sig_handlers[i].handler;
		act.sa_flags = default_flags ^ sig_handlers[i].override_flags;
		const int sig = sig_handlers[i].sig;
		if (sigaction(sig, &act, NULL) < 0) {
			syslog(LOG_USER|LOG_ERR, "Failed to set the handler for signal %d (%s) due to error: %s",
					sig, strsignal(sig), strerror(errno));
			ERR("Error registering a handler for signal", sig, strsignal(sig));
			rc = -1;
		}
	}

    return rc;
}


