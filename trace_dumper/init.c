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
#include <sys/mman.h>

#include "../trace_user.h"
#include "../opt_util.h"
#include "../trace_str_util.h"
#include "../trace_clock.h"
#include "trace_dumper.h"
#include "filesystem.h"
#include "buffers.h"
#include "init.h"
#include "open_close.h"

static struct trace_dumper_configuration_s trace_dumper_configuration;

static const char usage[] = {
    "Usage: %s [params]                                                                                            \n" \
    "                                                                                                              \n" \
    " -h, --help                            Display this help message                                              \n" \
    " -f  --filter [buffer_name]            Filter out specified buffer name                                       \n" \
    " -o  --online                          Show data from buffers as it arrives (slows performance)               \n" \
    " -n  --no-color                        Show online data without color                                         \n" \
    " -w  --write-to-file[filename]         Write log records to file                                              \n" \
    " -l  --low-latency-write[param=value]  Write to files in low-latency mode (which uses mmap), optionally specifying a parameter \n"
    "                                       This option may recur multiple times with different parameters. Recognized parameters: \n" \
    "                                           max_recs_pending:       Maximum number of records which haven't been confirmed to be committed to disk \n" \
    "                                           write_size_bytes:       The dumper should attempt to write n byte blocks aligned to n byte boundaries \n" \
    "                                           max_flush_interval_ms:  Maximum interval between flushes to disk (assuming there is data to be written) \n" \
    " -N  --notification-file[filename]     Write notifications (messages with severity > notification level) to a separate file\n" \
    " -L  --notification-level[level]       Specify minimum severity that will be written to the notification file (default: WARN)\n" \
    " -b  --logdir                          Specify the base log directory trace files are written to              \n" \
    " -p  --pid [pid]                       Attach the specified process                                           \n" \
    " -d  --debug-online                    Display DEBUG records in online mode                                   \n" \
    " -i  --info-online                     Dump info traces online                                                \n" \
    " -a  --warn-online                     Dump warning traces online                                             \n" \
    " -e  --error-online                    Dump error traces online                                               \n" \
    " -s  --syslog                          In online mode, write the entries to syslog instead of displaying them \n" \
    " -q  --quota-size [bytes/percent]      Specify the total number of bytes that may be taken up by trace files  \n" \
    " -r  --record-write-limit [records]    Specify maximal amount of records that can be written per-second (unlimited if not specified)  \n" \
    " -I  --instrument[option]               Turn on one of the dumper's instrumentation options. Available option values: time_writes \n"     \
    " -v  --dump-online-statistics          Dump buffer statistics \n"
    "\n"};

static const struct option longopts[] = {
    { "help", 0, 0, 'h'},
	{ "filter", required_argument, 0, 'f'},
	{ "online", 0, 0, 'o'},
    { "trace-online", 0, 0, 't'},
    { "debug-online", 0, 0, 'd'},
    { "info-online", 0, 0, 'i'},
    { "warn-online", 0, 0, 'a'},
    { "error-online", 0, 0, 'e'},
    { "logdir", required_argument, 0, 'b'},
	{ "no-color", 0, 0, 'n'},
    { "syslog", 0, 0, 's'},
    { "pid", required_argument, 0, 'p'},
    { "write-to-file", optional_argument, 0, 'w'},
    { "low-latency-write", optional_argument, 0, 'l'},
    { "notification-file",  optional_argument, 0, 'N'},
    { "notification-level", required_argument, 0, 'L'},
    { "quota-size", required_argument, 0, 'q'},
    { "record-write-limit", required_argument, 0, 'r'},
    { "instrument", required_argument, 0, 'I'},
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
    /* TODO: Make the following parameters configurable at runtime. */
    conf->notifications_subdir = "warn";
    conf->log_details = FALSE;

    /* Compiled-in defaults, can be overridden via the command-line */
    conf->max_records_pending_write_via_mmap = ULONG_MAX;
    conf->max_flush_interval = 1 * TRACE_SECOND;
    conf->preferred_flush_bytes = 0; /* Use page size */
}

//static
int parse_low_latency_mode_param(struct trace_dumper_configuration_s *conf, const char *arg)
{
	if (arg && *arg) {
		long long value = -1;
		const char *eq_sign = strchr(arg, '=');
		if (NULL == eq_sign) {
			return -1;
		}

		if (! trace_get_number(eq_sign + 1, &value)) {
			return -1;
		}

		const size_t param_name_len = eq_sign - arg;

#define is_param(s, param) ((sizeof(param) - 1 == param_name_len) && (0 == strncasecmp(s, param, param_name_len)))

		if (is_param(arg, "max_recs_pending")) {
			if (value > 0)
				conf->max_records_pending_write_via_mmap = value;
			else
				return -1;
		} else if (is_param(arg, "write_size_bytes")) {
			if (value >= 0)
				conf->preferred_flush_bytes = value;
			else
				return -1;
		} else if (is_param(arg, "max_flush_interval_ms")) {
			if (value >= 0)
				conf->max_flush_interval = TRACE_MS * value;
			else
				return -1;
		} else {
			return -1;
		}

#undef is_param

	}

	return 0;
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
        case 'o':
            conf->online = 1;
            break;
        case 'b':
            conf->logs_base = optarg;
            break;
        case 'n':
            conf->no_color_specified = 0;
            break;
        case 'p':
            conf->attach_to_pid = optarg;
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
        case 's':
            conf->syslog = 1;
            break;
        case 'q':
            conf->quota_specification = optarg;
            break;
        case 'r':
            conf->max_records_per_second = atoi(optarg);
            break;
        case 't':
            conf->trace_online = 1;
            break;
        case 'd':
            conf->debug_online = 1;
            break;
        case 'i':
            conf->info_online = 1;
            break;
        case 'a':
            conf->warn_online = 1;
            break;
        case 'e':
            conf->error_online = 1;
            break;
        case 'I':
        	if (0 == strcasecmp(optarg, "time_writes")) {
        		conf->log_performance_to_file = 1;
        	}
        	else {
        		fprintf(stderr, "Unrecognized trace dumper instrumentation option: %s", optarg);
        		return -1;
        	}
        	break;
        case 'v':
            conf->dump_online_statistics = 1;
            break;
        case '?':
            return -1;
            break;
        default:
            break;
        }
    }

    return 0;
}

#define ROTATION_COUNT 10
static const trace_ts_t FLUSH_DELTA = 5000;  /* In ns */

static int parser_event_handler(trace_parser_t __attribute__((unused)) *parser, enum trace_parser_event_e __attribute__((unused))event, void __attribute__((unused))*event_data, void __attribute__((unused)) *arg)
{
    return 0;
}

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

static void set_default_online_severities(struct trace_dumper_configuration_s *conf)
{
    conf->info_online = 1;
    conf->warn_online = 1;
    conf->error_online = 1;
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
    assert(0 == atexit(TRACE__fini));
#endif
}

int init_dumper(struct trace_dumper_configuration_s *conf)
{
    set_trace_cleanup_for_dumper();
    clear_mapped_records(conf);

    if (!conf->write_to_file && !conf->online && conf->dump_online_statistics) {
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

    TRACE_PARSER__from_external_stream(&conf->parser, parser_event_handler, NULL);
    TRACE_PARSER__set_indent(&conf->parser, TRUE);
    TRACE_PARSER__set_show_field_names(&conf->parser, TRUE);

    TRACE_PARSER__set_relative_ts(&conf->parser, TRUE);
    if (conf->no_color_specified) {
        conf->color = 0;
        TRACE_PARSER__set_color(&conf->parser, FALSE);
    } else {
        conf->color = 1;
        TRACE_PARSER__set_color(&conf->parser, TRUE);
    }

    if (conf->syslog) {
        openlog("traces", 0, 0);
        TRACE_PARSER__set_indent(&conf->parser, 0);
        TRACE_PARSER__set_color(&conf->parser, 0);
        TRACE_PARSER__set_show_timestamp(&conf->parser, 0);
        TRACE_PARSER__set_show_field_names(&conf->parser, 0);
    }

    unsigned int severity_mask = get_allowed_online_severity_mask(conf);
    if (0 == severity_mask) {
        set_default_online_severities(conf);
        severity_mask = get_allowed_online_severity_mask(conf);
    }

    if (conf->trace_online) {
        TRACE_PARSER__set_indent(&conf->parser, TRUE);
    } else {
        TRACE_PARSER__set_indent(&conf->parser, FALSE);
    }

    if (conf->minimal_notification_severity < TRACE_SEV__MIN) {
    	conf->minimal_notification_severity = TRACE_SEV_WARN;
    }

    TRACE_PARSER__matcher_spec_from_severity_mask(severity_mask, conf->severity_filter, ARRAY_LENGTH(conf->severity_filter));
    TRACE_PARSER__set_filter(&conf->parser, conf->severity_filter);
    TRACE_PARSER__set_free_dead_buffer_contexts(&conf->parser, TRUE);

    if (set_quota(conf) != 0) {
        return EX_IOERR;
    }

    if (conf->low_latency_write) {
    	syslog(LOG_USER|LOG_INFO,
    			"Trace dumper is writing records in low latency mode using memory mappings, with max_recs_pending=%lu (0x%lX), write_size_bytes=%lu (0x%lX), max_flush_interval_ms=%.3f sec",
    			conf->max_records_pending_write_via_mmap, conf->max_records_pending_write_via_mmap,
    			conf->preferred_flush_bytes, conf->preferred_flush_bytes,
    			conf->max_flush_interval / (double) TRACE_SECOND);
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
		assert(0);
		return;
	}

	request_file_operations(&trace_dumper_configuration, op_flags);
}

int set_signal_handling(void)
{
	static const int default_flags = SA_SIGINFO|SA_RESTART;
	int rc = 0;
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
		if (sigaction(sig_handlers[i].sig, &act, NULL) < 0) {
			syslog(LOG_USER|LOG_ERR, "Failed to set the handler for signal %d (%s) due to error: %s",
					sig_handlers[i].sig, strsignal(sig_handlers[i].sig), strerror(errno));
					rc |= -1;
		}
	}

    return rc;
}


