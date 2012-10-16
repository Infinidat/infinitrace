#define _XOPEN_SOURCE

#include "../trace_parser.h"
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <limits.h>
#include <getopt.h>
#include <sysexits.h>
#include "../list_template.h"
#include "../array_length.h"

enum op_type_e {
    OP_TYPE_INVALID,
    OP_TYPE_DUMP_STATS,
    OP_TYPE_DUMP_FILE,
    OP_TYPE_DUMP_METADATA
};

typedef struct trace_record_matcher_spec_s filter_t;

struct trace_reader_conf {
    enum op_type_e op_type;
    unsigned int severity_mask;
    int tail;
    int no_color;
    int hex;
    int show_field_names;
    int relative_ts;
    int compact_trace;
    int free_dead_process_metadata;
    long long from_time;
    const char **files_to_process; /* A NULL terminated array of const char* */
    filter_t severity_filter[SEVERITY_FILTER_LEN];

    filter_t * filter_function; // TODO - not supported by parser yet
    filter_t * filter_grep;
    filter_t * filter_value;
    filter_t * filter_fuzzy;
};

static const char *usage = 
    "Usage: %s [params] [files]\n"
    "Actions:\n"
    " -h, --help                 Display this help message                               \n"
    " -i  --tail                 Display last records and wait for more data             \n"
    " -s  --print-stats          Print per-log occurrence count                          \n"
    " -d  --dump                 Dump contents of trace file (default)                   \n"
    " -e  --dump-debug           Dump all debug entries                                  \n"
    " -f  --dump-functions       Dump all debug entries and function calls               \n"
    " -m  --dump-metadata        Dump metadata                                           \n"
    "Displays:\n"
    " -n  --no-color             Disable colored output                                  \n"
    " -o  --show-field-names     Show field names for all trace records                  \n"
    " -r  --relative-timestamp   Print timestamps relative to boot time                  \n"
    " -x  --hex                  Display all numeric values in hexadecimal               \n"
    " -c  --compact-traces       Compact trace output                                    \n"
    "Filters: \n"
    " -t  --time   [time]     : Show records beginning with [time], format follows trace output timestamps \n"
    " -g  --grep   [str]      : Show records whose constant string matches [str]  \n"
    " -v  --value  [num ]     : Show records with int value equal to [num]         \n"
    " -v  --value  [name=num] : Show records with specific name field [name] equal to [num] (as name apears with -o)\n"
    " -z  --fuzzy  [??? ]     : - If [???] looks like a number, similar to -v [num], else similar to -g [str]\n"
    "Filters Rules & Examples:\n"
    "  Differnt options are bound with AND\n"
    "  Filter options can be repeated, repetitions are bound with OR (exceptioned by -t)\n"
    "  Enums can be filtered as literal numbers (parsing not implemented yet)\n"
    " '-g snap -v a_vu=0 -v 333 -g remove' means 'str(snap) && (named_val(a_vu, 0) || val(333)) && str(remove)\n"
    " '-g str1 -v 111 -z 222 -z 333 -z str2' means 'str(str1) && val(111) && (val(222) || val(333) || str(str2))'\n"
    //    " -u  --function  [func]     Show only records generated from function [func]               \n"

    "\n";

static const struct option longopts[] = {
    { "help", 0, 0, 'h'},
	{ "dump", 0, 0, 'd'},
	{ "no-color", 0, 0, 'n'},
    { "dump-debug", 0, 0, 'e'},
    { "dump-functions", 0, 0, 'f'},
    { "dump-metadata", 0, 0, 'm'},
    { "print-stats", 0, 0, 's'},
    { "show-field-name", 0, 0, 'o'},
    { "relative-timestamp", required_argument, 0, 't'},
    { "grep", required_argument, 0, 'g'},
    // { "function", required_argument, 0, 'u'},
    { "value", required_argument, 0, 'v'},
    { "fuzzy", required_argument, 0, 'z'},
    { "hex", 0, 0, 'x'},
    { "tail", 0, 0, 'i'},
    { "compact-trace", 0, 0, 'c'},
	{ 0, 0, 0, 0}
};

static void print_usage(const char *prog_name)
{
    fprintf(stderr, usage, prog_name);
}

static const char shortopts[] = "hisdefmnorxcg:v:V:t:z:"; // " xcig:u:v:V:moft:hdnesr";

#define SECOND (1000000000LL)
#define MINUTE (SECOND * 60LL)
#define HOUR (MINUTE * 60LL)
#define DAY (HOUR * 24LL)
#define YEAR (DAY * 365LL)

static long long timespec_to_nanosec(struct tm *time_spec)
{
    return (mktime(time_spec) * SECOND);
}

static long long maybe_process_nanosec(const char *str)
{
    if (*str == ':') {
        long long nano_seconds = strtoll(&str[1], NULL, 10);
        if (nano_seconds == LLONG_MAX || nano_seconds == LLONG_MIN) {
            return 0;
        } else {
            return nano_seconds;
        }
    } else {
        return 0;
    }
}

static unsigned long long format_cmdline_time(const char *time_str)
{
    const char *format = "%a %b %d %T %Y";
    struct tm formatted_time;
    memset(&formatted_time, 0, sizeof(formatted_time));
    formatted_time.tm_isdst=-1;
    char *result = strptime(time_str, format, &formatted_time);
    if (NULL == result) {
        return LLONG_MIN;
    } else {
        long long from_time = timespec_to_nanosec(&formatted_time);
        from_time += maybe_process_nanosec(result);
        return from_time;
    }
}

static filter_t *new_filter_t() {
    filter_t* ret = malloc(sizeof(filter_t));
    memset(ret, 0, sizeof(*ret));
    return ret;
}

static void and_filter(filter_t *filter_a,
                       filter_t *filter_b) {

    filter_t * filter_dup_a = new_filter_t();
    memcpy(filter_dup_a, filter_a, sizeof(*filter_a));
    filter_a->type = TRACE_MATCHER_AND;
    filter_a->u.binary_operator_parameters.a = filter_dup_a;
    filter_a->u.binary_operator_parameters.b = filter_b;
}

static void or_filter(filter_t *filter_a,
                      filter_t *filter_b) {

    filter_t * filter_dup_a = new_filter_t();
    memcpy(filter_dup_a, filter_a, sizeof(*filter_a));
    filter_a->type = TRACE_MATCHER_OR;
    filter_a->u.binary_operator_parameters.a = filter_dup_a;
    filter_a->u.binary_operator_parameters.b = filter_b;
}

static int is_number(char* str) {
    if (! (str && *str))
        return 0;
    while  (*str) {
        if (*str < '0' || *str > '9')
            return 0;
        str++;
    }
    return 1;
}

static int parse_command_line(struct trace_reader_conf *conf, int argc, const char **argv)
{
    int o;
    int longindex;
    conf->severity_mask = ((1 << TRACE_SEV_TRIO) | (1 << TRACE_SEV_INFO) | (1 << TRACE_SEV_NOTE) | (1 << TRACE_SEV_WARN) | (1 << TRACE_SEV_ERR) | (1 << TRACE_SEV_FATAL));
    while ((o = getopt_long(argc, (char **)argv, shortopts, longopts, &longindex)) != EOF) {
		switch (o) {
		case 'h':
		case '?':
			return 1;
		case 'd':
            conf->op_type = OP_TYPE_DUMP_FILE;
            break;
        case 'e':
            conf->severity_mask = conf->severity_mask | (1 << TRACE_SEV_DEBUG);
            break;
        case 'f':
            conf->severity_mask = conf->severity_mask | (1 << TRACE_SEV_FUNC_TRACE) | (1 << TRACE_SEV_DEBUG);
            break;
		case 's':
			conf->op_type = OP_TYPE_DUMP_STATS;
			break;
        case 'n':
            conf->no_color = 1;
            break;
        case 'r':
            conf->relative_ts = 1;
            break;
        case 'i':
            conf->tail = 1;
            break;
        case 'c':
            conf->compact_trace = 1;
            break;
        case 't':
            conf->from_time = format_cmdline_time(optarg);
            if (conf->from_time == LLONG_MIN || conf->from_time == LLONG_MAX) {
                fprintf(stderr, "Invalid time specification\n");
                return -1;
            }
            break;
        case 'm':
            conf->op_type = OP_TYPE_DUMP_METADATA;
            break;
        case 'g':
            {
                filter_t * f = new_filter_t();
                f->type = TRACE_MATCHER_CONST_SUBSTRING;
                strncpy(f->u.const_string, optarg, sizeof(f->u.const_string));
                if (conf->filter_grep == NULL )
                    conf->filter_grep = f;
                else
                    or_filter(conf->filter_grep, f);
            }
            break;
        case 'v':
            {
                filter_t * f = new_filter_t();
                char* equal = rindex(optarg, '=');
                if (equal) {
                    if (equal > sizeof(f->u.named_param_value.param_name) + optarg) {
                        fprintf(stderr, "'%s': Too long.", optarg);
                        return -1;
                    }
                    f->type = TRACE_MATCHER_LOG_NAMED_PARAM_VALUE;
                    f->u.named_param_value.param_value = atoll(equal+1);
                    strncpy(f->u.named_param_value.param_name, optarg, equal-optarg);
                }
                else {
                    f->type = TRACE_MATCHER_LOG_PARAM_VALUE;
                    f->u.param_value = atoll(optarg);
                }
                if (conf->filter_value == NULL)
                    conf->filter_value = f;
                else
                    or_filter(conf->filter_value, f);
            }
            break;
        case 'z':
            {
                filter_t * f = new_filter_t();
                if (is_number(optarg)) {
                    f->type = TRACE_MATCHER_LOG_PARAM_VALUE;
                    f->u.param_value = atoll(optarg);
                }
                else {
                    f->type = TRACE_MATCHER_CONST_SUBSTRING;
                    strncpy(f->u.const_string, optarg, sizeof(f->u.const_string));
                }
                if (conf->filter_fuzzy == NULL )
                    conf->filter_fuzzy = f;
                else
                    or_filter(conf->filter_fuzzy, f);
            }
            break;
        case 'o':
            conf->show_field_names = TRUE;
            break;
        case 'x':
            conf->hex = TRUE;
            break;
        default:
            break;
        }
    }

    if (conf->op_type == OP_TYPE_INVALID) // make it the default
        conf->op_type = OP_TYPE_DUMP_FILE;

    unsigned long filename_index = optind;
    conf->files_to_process = argv + (int)filename_index;
    if (NULL == *(conf->files_to_process)) {
    	fprintf(stderr, "simple_trace_reader: Must specify input files\n");
    	return -1;
    }

    return 0;
}

int read_event_handler(struct trace_parser  __attribute__((unused)) *parser, enum trace_parser_event_e  __attribute__((unused)) event, void  __attribute__((unused)) *event_data, void  __attribute__((unused)) *arg)
{
    return 0;
}

static void set_parser_filter(struct trace_reader_conf *conf, trace_parser_t *parser)
{
    TRACE_PARSER__matcher_spec_from_severity_mask(conf->severity_mask, conf->severity_filter, ARRAY_LENGTH(conf->severity_filter));
    filter_t *filter = conf->severity_filter;
    if (conf->filter_grep)
        and_filter(filter, conf->filter_grep);

    if (conf->filter_value)
        and_filter(filter, conf->filter_value);

    if (conf->filter_fuzzy)
        and_filter(filter, conf->filter_fuzzy);

    TRACE_PARSER__set_filter(parser, filter);
    
}

static void set_parser_params(struct trace_reader_conf *conf, trace_parser_t *parser)
{
    set_parser_filter(conf, parser);
    TRACE_PARSER__set_color(parser, FALSE == conf->no_color);
    TRACE_PARSER__set_indent(parser, 0 != (conf->severity_mask & (1 << TRACE_SEV_FUNC_TRACE)));
    TRACE_PARSER__set_relative_ts(parser, FALSE != conf->relative_ts);
    TRACE_PARSER__set_show_field_names(parser, FALSE != conf->show_field_names);
    TRACE_PARSER__set_compact_traces(parser, FALSE != conf->compact_trace);
    TRACE_PARSER__set_always_hex(parser, FALSE != conf->hex);
    TRACE_PARSER__set_free_dead_buffer_contexts(parser, FALSE != conf->free_dead_process_metadata);
}

static int dump_all_files(struct trace_reader_conf *conf)
{
    int error_occurred = 0;
    const char **filenames;
    trace_parser_t parser;
    conf->free_dead_process_metadata = TRUE;
    
    for (filenames = conf->files_to_process; *filenames; filenames++) {
    	const char *filename = *filenames;
        int rc = TRACE_PARSER__from_file(&parser, conf->tail, filename, read_event_handler, NULL);
        if (0 != rc) {
            fprintf(stderr, "Error opening file %s (%s)\n", filename, strerror(errno));
            return EX_NOINPUT;
        }
        set_parser_params(conf, &parser);

        unsigned long long seek_ts = 0;
        if (conf->from_time) {
        	seek_ts = conf->from_time;
        } else if (conf->tail) {
        	seek_ts = LLONG_MAX;
        }

        if (seek_ts > 0) {
        	TRACE_PARSER__seek_to_time(&parser, seek_ts, &error_occurred);
        	if (error_occurred) {
        		fprintf(stderr, "Failed to seek to %s in the file %s due to error %s\n",
        				conf->tail ? "the end" : "the requested time", filename, strerror(error_occurred));
        	}
        }

        if ((!error_occurred) && (TRACE_PARSER__dump(&parser) < 0)) {
        	error_occurred = errno;
        	fprintf(stderr, "Record dumping from the file %s failed due to error: %s\n", filename, strerror(error_occurred));
        }
        TRACE_PARSER__fini(&parser);
    }

    if (error_occurred) {
    	fprintf(stderr, "Trace has reader encountered the following error: %s",  strerror(error_occurred));
    	return EX_IOERR;
    }

    return 0;
}

static int dump_statistics_for_all_files(struct trace_reader_conf *conf)
{
    const char **filenames;
    trace_parser_t parser;
    int error_occurred = 0;
    conf->free_dead_process_metadata = FALSE;
    
    for (filenames = conf->files_to_process; *filenames; filenames++) {
     	const char *filename = *filenames;
        int rc = TRACE_PARSER__from_file(&parser, FALSE, filename, read_event_handler, NULL);
        if (0 != rc) {
            fprintf(stderr, "Error opening file %s: %s\n", filename, strerror(errno));
            return EX_NOINPUT;
        }

        set_parser_params(conf, &parser);

        if (TRACE_PARSER__dump_statistics(&parser) < 0) {
        	error_occurred = errno;
        	fprintf(stderr, "Error producing statistics from the file file %s: %s\n", filename, strerror(error_occurred));
        }
        TRACE_PARSER__fini(&parser);
    }

    return error_occurred ? EX_IOERR : 0;
}

static int dump_metadata_for_files(struct trace_reader_conf *conf)
{
    trace_parser_t parser;
    int error_occurred = 0;
    const char **filenames;
    conf->free_dead_process_metadata = FALSE;
    
    for (filenames = conf->files_to_process; *filenames; filenames++) {
     	const char *filename = *filenames;

        int rc = TRACE_PARSER__from_file(&parser, FALSE, filename, read_event_handler, NULL);
        set_parser_params(conf, &parser);

        if (0 != rc) {
            fprintf(stderr, "Error opening file %s\n", filename);
            return EX_NOINPUT;
        }

        if (TRACE_PARSER__dump_statistics(&parser) < 0) {
			error_occurred = errno;
			fprintf(stderr, "Error producing statistics from the file file %s: %s\n", filename, strerror(error_occurred));
		}

        TRACE_PARSER__dump_all_metadata(&parser);
        TRACE_PARSER__fini(&parser);
    }

    return error_occurred ? EX_IOERR : 0;
}

int main(int argc, const char **argv)
{
    struct trace_reader_conf conf;
    memset(&conf, 0, sizeof(conf));
    conf.severity_mask = ((1 << TRACE_SEV_DEBUG) | (1 << TRACE_SEV_FUNC_TRACE));
    int rc = parse_command_line(&conf, argc, argv);
    if (0 != rc) {
    	print_usage(argv[0]);
        return (rc < 0) ? EX_USAGE : 0;
    }

    switch (conf.op_type) {
    case OP_TYPE_DUMP_STATS:
        return dump_statistics_for_all_files(&conf);
        break;
    case OP_TYPE_DUMP_FILE:
        return dump_all_files(&conf);
        break;
    case OP_TYPE_DUMP_METADATA:
        return dump_metadata_for_files(&conf);
        break;
    case OP_TYPE_INVALID:
        fprintf(stderr, "simple_trace_reader: Must specify operation type (-s or -d)\n");
        print_usage(argv[0]);
        return EX_USAGE;
    default:
        break;
    }
    
    return 0;
}
