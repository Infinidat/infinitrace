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
#include <getopt.h>
#include <signal.h>
#include <sysexits.h>
#include <syslog.h>
#include <errno.h>
#include <limits.h>

#include "../trace_user.h"
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
    " -w  --write-to-file[filename]         Write log records to file                                              \n" \
    " -b  --logdir                          Specify the base log directory trace files are written to              \n" \
    " -p  --pid [pid]                       Attach the specified process                                           \n" \
    " -d  --debug-online                    Display DEBUG records in online mode                                   \n" \
    " -i  --info-online                     Dump info traces online                                                \n" \
    " -a  --warn-online                     Dump warning traces online                                             \n" \
    " -e  --error-online                    Dump error traces online                                               \n" \
    " -s  --syslog                          In online mode, write the entries to syslog instead of displaying them \n" \
    " -q  --quota-size [bytes/percent]      Specify the total number of bytes that may be taken up by trace files  \n" \
    " -r  --record-write-limit [records]    Specify maximal amount of records that can be written per-second (unlimited if not specified)  \n" \
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
    { "write", optional_argument, 0, 'w'},
    { "quota-size", required_argument, 0, 'q'},
    { "record-write-limit", required_argument, 0, 'r'},
    { "dump-online-statistics", 0, 0, 'v'},

	{ 0, 0, 0, 0}
};

void print_usage(const char *prog_name)
{
	const char *display_name = (NULL == prog_name) ? "trace_dumper" : prog_name;
    printf(usage, display_name);
}

static const char shortopts[] = "vtdiaer:q:sw::p:hf:ob:n";

#define DEFAULT_LOG_DIRECTORY "/mnt/logs/traces"

int parse_commandline(struct trace_dumper_configuration_s *conf, int argc, char **argv)
{
    int o;
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
    	syslog(LOG_USER|LOG_INFO, "Trace dumper quota is set to %lld records per log directory, in %llu record files",
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


int init_dumper(struct trace_dumper_configuration_s *conf)
{
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
    conf->ts_flush_delta = FLUSH_DELTA;
    conf->flush_iovec_total_records = 0;
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

    TRACE_PARSER__matcher_spec_from_severity_mask(severity_mask, conf->severity_filter, ARRAY_LENGTH(conf->severity_filter));
    TRACE_PARSER__set_filter(&conf->parser, conf->severity_filter);
    TRACE_PARSER__set_free_dead_buffer_contexts(&conf->parser, TRUE);

    if (set_quota(conf) != 0) {
        return EX_IOERR;
    }

    return 0;
}

struct trace_dumper_configuration_s *trace_dumper_get_configuration()
{
	return &trace_dumper_configuration;
}


/* Signal handling */

static void usr1_handler()
{
	close_record_file_if_necessary(&trace_dumper_configuration);
}

static void usr2_handler()
{
	close_record_file_if_necessary(&trace_dumper_configuration);

	static const char snapshot_prefix[] = "snapshot.";

    int rc = prepend_prefix_to_filename(trace_dumper_configuration.record_file.filename, snapshot_prefix);
    if (0 != rc) {
    	syslog(LOG_USER|LOG_ERR, "Trace dumper failed to create a snapshot of file %s due to error: %s",
    			trace_dumper_configuration.record_file.filename, strerror(errno));
        ERR("Error prefixing",  trace_dumper_configuration.record_file.filename, "(", strerror(errno), ")");
    } else {
        INFO("Created snapshot file at", snapshot_prefix, trace_dumper_configuration.record_file.filename);
    }
}

int set_signal_handling(void)
{
	const struct {
		int sig;
		sig_t handler;
	} sig_handlers[] = {
		{ SIGUSR1, usr1_handler },
		{ SIGUSR2, usr2_handler },
	};

	unsigned i;
	for (i = 0; i < ARRAY_LENGTH(sig_handlers); i++) {
		if (SIG_ERR == signal(sig_handlers[i].sig, sig_handlers[i].handler)) {
			syslog(LOG_USER|LOG_ERR, "Failed to set the handler for signal %d due to error: %s", sig_handlers[i].sig, strerror(errno));
			return -1;
		}
	}

    return 0;
}


