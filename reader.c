#define _XOPEN_SOURCE

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

#include "parser.h"
#include "list_template.h"
#include "array_length.h"
#include "timeformat.h"

enum op_type_e {
    OP_TYPE_INVALID,
    OP_TYPE_DUMP_STATS,
    OP_TYPE_DUMP_FILE,
    OP_TYPE_DUMP_METADATA
};

typedef struct trace_record_matcher_spec_s filter_t;

struct trace_reader_conf {
    enum op_type_e op_type;
    int severity_level;
    int tail;
    int no_color;
    int hex;
    int show_field_names;
    int show_trace_file;
    int hide_funtion_name;
    int nanoseconds_ts;
    int empty_timestamp;
    int compact_trace;
    int free_dead_process_metadata;
    // long long from_time;
    int after_count;
    const char **files_to_process; /* A NULL terminated array of const char* */

    filter_t * filter_function; // TODO - not supported by parser yet
    filter_t * filter_grep;
    filter_t * filter_strcmp;    
    filter_t * filter_value;
    filter_t * filter_value2;
    filter_t * filter_value3;
    filter_t * filter_fuzzy;
    filter_t * filter_time;
    filter_t * filter_quota;
};

static const char *usage = 
    "Usage: %s [params] file[s]\n\
    Actions:\n\
     (DEFAULT ACTION)    : Dump contents of trace file \n\
 -s  --print-stats       : Print per-log occurrence count \n\
 -m  --dump-metadata     : Dump metadata \n\
 -i  --tail              : Display last records and wait for more data \n\
 -h, --help              : Display this help message \n\
 \n\
    Displays: \n\
 -N  --no-color          : Disable colored output \n\
 -O  --show-field-names  : Show field names for all trace records \n\
 -X  --hex               : Display all numeric values in hexadecimal \n\
 -F  --hide-function     : As the name implies, avoid displaying function names \n\
 -L  --show-trace-file   : Display faked log messages with trace's file name \n\
 -E  --hide-timestamp    : Hide timestamp and process name/id (mnemonic - Empty) \n\
 -M  --compact-traces    : Compact trace output \n\
 -P  --nano-timestamp    : Print timestamps as raw nano-seconds-since-Epoch units \n\
 -Q  --quota-max [num]   : Show no more than [num] traces (technicaly it's a filter, but 'gimme a break) \n\
 -A  --after     [num]   : Show [num] traces of the same thread after each hit (TBD: -B/C) \n\
 \n\
    Filters: \n\
 -l  --level  [severity] : Show records from severity and up. Int value or FUNC/DEBUG/INFO/WARN/ERR/FATAL (DEFAULT: INFO) \n\
 -t  --time   [time]     : Used once or twice to set a time range. [time] may be nanoseconds int, or time format string \n\
 -g  --grep   [str]      : Show records whose constant string contains [str] \n\
 -c  --strcmp [str]      : Show records whose constant string exact-matches [str] (faster than -g, useful to filter MODULE)\n\
 -v  --value  [num ]     : Show records with int value equal to [num] \n\
 -v  --value  [name=num] : Show records with specific name field [name] equal to [num] (as name apears with -O) \n\
 -u  --value2 [num] or [name=num] : similar to -v \n\
 -w  --value3 [num] or [name=num] : similar to -v and -u \n\
 -z  --fuzzy  [??? ]     : - If [???] looks like a number, similar to -v [num], else similar to -g [str] \n\
 -f  --function [func]   : Show only traces generated by [func] (exact match) \n\
 \n\
    Filters Rules: \n\
 * legal -t values: '2012/09/03_05:10:56_676665242', '2012/09/03_05:10:56' (zero padded), '1346649056676293891' (as in -P) \n\
 * Differnt options are bound with AND \n\
 * Filter options can be repeated, repetitions are bound with OR (exceptioned by -t) \n\
 * Enums can be filtered as literal numbers (named enums - TBD) \n\
 * Instead of 'name=num' one can use 'name<num' or 'name>num' (quote to avoid shell's redirection, unsigned only) \n\
    Examples: \n\
 '-l WARN'                               shows warnings, errors, and fatal traces\n\
 '-g snap -v a_vu=0 -v 333 -g remove'    means 'str(snap) && (named_val(a_vu, 0) || val(333)) && str(remove) \n\
 '-g str1 -v 111 -z 222 -z 333 -z str2'  means 'str(str1) && val(111) && (val(222) || val(333) || str(str2))' \n\
 '-c CACHE -v a_lba=1442'                means 'CACHE && lba(1442)' \n\
 '-c CACHE -v a_lba=1442' -v a_lba=1444' means 'CACHE && (lba(1442) || lab(1444))' \n\
 \"-v 'vu<4' -w 'vu>1' -Q20 \"           same as '-v vu=2 -v -Q20' \n\
\n";
    //    " -u  --function  [func]     Show only records generated from function [func] 

static const struct option longopts[] = {
    { "help"            , 0, 0, 'h'},
    { "dump-metadata"   , 0, 0, 'm'},
	// { "dump"            , 0, 0, 'd'},
    { "print-stats"     , 0, 0, 's'},
    { "tail"            , 0, 0, 'i'},

    { "show-field-name" , 0, 0, 'O'},
    { "hide-function"   , 0, 0, 'F'},
	{ "no-color"        , 0, 0, 'N'},
    { "hex"             , 0, 0, 'X'},
    { "hide-timestamp"  , 0, 0, 'E'},
    { "show-trace-file" , 0, 0, 'L'},
    { "compact-trace"   , 0, 0, 'M'},
    { "nano-timestamp"  , 0, 0, 'P'},
    { "quota-max"       , required_argument, 0, 'Q'},

    { "level"           , required_argument, 0, 'l'},
    { "time"            , required_argument, 0, 't'},
    { "grep"            , required_argument, 0, 'g'},
    { "strcmp"          , required_argument, 0, 'c'},
    { "value"           , required_argument, 0, 'v'},
    { "value2"          , required_argument, 0, 'u'},
    { "value3"          , required_argument, 0, 'w'},
    { "fuzzy"           , required_argument, 0, 'z'},
    { "function"        , required_argument, 0, 'f'},
	{ 0, 0, 0, 0}
};

static const char shortopts[] = "hisdm NOFLXEMPA:Q: g:c:v:u:w:t:z:l:f:"; // " xcig:u:v:V:moft:hdnesr";

static int exit_usage(const char *prog_name, const char* more)
{
    if (prog_name) {
        fprintf(stderr, usage, prog_name);
        if (!more)
            exit(0);
        fprintf(stderr, "\n%s\n", more);
        exit(EX_USAGE);
    }

    fprintf(stderr, "%s\n%s\n", more, "    Please use --help option (-h) for full usage ");
    exit(EX_USAGE);
    return 0;                   /* happy compiler */
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

static int get_number(const char* str, long long *num) { /* home made atoll / strtoll */
    if (! (str && *str)) return 0;
    int negative = 0;
    long long n = 0;
    if (str[0] == '-' || str[0] == '+') {
        negative = str[0] == '-';
        str++;
    }
    if (str[0] == '0' && (str[1] | 0x20) == 'x') {
        str += 2;
        while (*str) {
            if ((*str < '0' || *str > '9') && ((*str|0x20) < 'a' || (*str|0x20) > 'f'))
                return 0;
            n *= 0x10;
            n += (*str > '9') ? ((*str|0x20) - 'W') : *str-'0';
            str++;
        }
    }
    else {
        while  (*str) {
            if (*str < '0' || *str > '9')
                return 0;
            n *= 10;
            n += *str - '0';
            str++;
        }
    }
    *num = negative ? 0-n : n;
    return 1;
}

static int get_severity_level(const char* str) {
    long long n;
    return 
        get_number(str, &n)           ? n :
        0 == strcasecmp(str, "FUNC" ) ? 1 :
        0 == strcasecmp(str, "DEBUG") ? 2 :
        0 == strcasecmp(str, "INFO" ) ? 3 :
        0 == strcasecmp(str, "WARN" ) ? 4 :
        0 == strcasecmp(str, "ERR"  ) ? 5 :
        0 == strcasecmp(str, "FATAL") ? 6 :
        exit_usage(NULL, "Severity format may be a number, or FUNC/DEBUG/INFO/WARN/ERR/FATAL");
}

static int parse_command_line(struct trace_reader_conf *conf, int argc, const char **argv)
{
    int o;
    int longindex;
    long long num;
    conf->op_type = OP_TYPE_DUMP_FILE;

    while ((o = getopt_long(argc, (char **)argv, shortopts, longopts, &longindex)) != EOF) {
		switch (o) {
		case 'h':
		case '?':
			return 1;
		case 'd':
            conf->op_type = OP_TYPE_DUMP_FILE;
            break;
        case 'l':
            conf->severity_level = get_severity_level(optarg);
            break;
		case 's':
			conf->op_type = OP_TYPE_DUMP_STATS;
			break;

        case 'O':
            conf->show_field_names = TRUE;
            break;
        case 'F':
            conf->hide_funtion_name = TRUE;
            break;
        case 'L':
            conf->show_trace_file = TRUE;
            break;
        case 'X':
            conf->hex = TRUE;
            break;
        case 'N':
            conf->no_color = 1;
            break;
        case 'E':
            conf->empty_timestamp = 1;
            break;
        case 'M':
            conf->compact_trace = 1;
            break;
        case 'P':
            conf->nanoseconds_ts = 1;
            break;

        case 'i':
            conf->tail = 1;
            break;
        case 'm':
            conf->op_type = OP_TYPE_DUMP_METADATA;
            break;
            /* Filters */
        case 'Q':
            {
                if (!get_number(optarg, &num))
                    exit_usage(NULL, "-Q [val] : [val] must be a legal number");
                if (num <= 0)
                    exit_usage(NULL, "-Q [val] : [val] must be a positive number");
                conf->filter_quota = new_filter_t();
                conf->filter_quota->type = TRACE_MATCHER_QUOTA_MAX;
                conf->filter_quota->u.quota_max = num;
            }
            break;
        case 'A':
            {
                if (! get_number(optarg, &num))
                    exit_usage(NULL, "-A [val] : [val] must be a legal (positive) number");
                conf->after_count = num > 0 ? num : 0;
            }
            break;
        case 't':
            {
                unsigned long long nanosec = str_to_nano_seconds(optarg);
                if (conf->filter_time == NULL) {
                    conf->filter_time = new_filter_t();
                    conf->filter_time->type = TRACE_MATCHER_TIMERANGE;
                    conf->filter_time->u.time_range.start = nanosec;
                    conf->filter_time->u.time_range.end   = LLONG_MAX;
                }
                else if (nanosec < conf->filter_time->u.time_range.start) {
                    conf->filter_time->u.time_range.end =
                    conf->filter_time->u.time_range.start;
                    conf->filter_time->u.time_range.start = nanosec;
                }
                else
                    conf->filter_time->u.time_range.end   = nanosec;
            }
            break;

#define WITH(FILTER) if (conf->FILTER == NULL) conf->FILTER = f; else or_filter(conf->FILTER, f)
        case 'g':
            {
                filter_t * f = new_filter_t();
                f->type = TRACE_MATCHER_CONST_SUBSTRING;
                strncpy(f->u.const_string, optarg, sizeof(f->u.const_string));
                WITH(filter_grep);
            }
            break;

        case 'c':
            {
                filter_t * f = new_filter_t();
                f->type = TRACE_MATCHER_CONST_STRCMP;
                strncpy(f->u.const_string, optarg, sizeof(f->u.const_string));
                WITH(filter_strcmp);
            } break;

        case 'w':
        case 'v':
        case 'u':
            {
                filter_t * f = new_filter_t();
                char* equal = NULL ; 
        #define OR_MAYBE(C) if (! equal ) equal = rindex(optarg, C)
                OR_MAYBE('=');
                OR_MAYBE('>');
                OR_MAYBE('<');
        #undef  OR_MAYBE
                if (equal) {
                    if (equal > sizeof(f->u.named_param_value.param_name) + optarg) {
                        fprintf(stderr, "'%s': Too long.", optarg);
                        return -1;
                    }
                    if (!get_number(equal+1, &num))
                        exit_usage(NULL, " Bad integer number in named value");
                    f->type = TRACE_MATCHER_LOG_NAMED_PARAM_VALUE;
                    f->u.named_param_value.param_value = num;
                    f->u.named_param_value.compare_type = *equal;
                    strncpy(f->u.named_param_value.param_name, optarg, equal-optarg);
                }
                else {
                    if (!get_number(optarg, &num))
                        exit_usage(NULL, " Bad integer number in value");
                    f->type = TRACE_MATCHER_LOG_PARAM_VALUE;
                    f->u.named_param_value.param_value = num;
                    f->u.named_param_value.compare_type = '=';
                }
                if      (o == 'v') { WITH(filter_value ); }
                else if (o == 'u') { WITH(filter_value2); }
                else               { WITH(filter_value3); }
            }
            break;
        case 'z':
            {
                filter_t * f = new_filter_t();
                if (get_number(optarg, &num)) {
                    f->type = TRACE_MATCHER_LOG_PARAM_VALUE;
                    f->u.named_param_value.param_value = num;
                    f->u.named_param_value.compare_type = '=';
                }
                else {
                    f->type = TRACE_MATCHER_CONST_SUBSTRING;
                    strncpy(f->u.const_string, optarg, sizeof(f->u.const_string));
                }
                WITH(filter_fuzzy);
            }
            break;
        case 'f':
            {
                filter_t * f = new_filter_t();
                f->type = TRACE_MATCHER_FUNCTION_NAME;
                strncpy(f->u.function_name, optarg, sizeof(f->u.function_name));
                WITH(filter_function);
            }
            break;
#undef WITH
        default:
            conf->op_type = OP_TYPE_INVALID;
            break;
        }
    }

    unsigned long filename_index = optind;
    conf->files_to_process = argv + (int)filename_index;
    if (NULL == *(conf->files_to_process))
    	exit_usage(NULL, "Must specify input files");

    return 0;
}

int read_event_handler(struct trace_parser  __attribute__((unused)) *parser, enum trace_parser_event_e  __attribute__((unused)) event, void  __attribute__((unused)) *event_data, void  __attribute__((unused)) *arg)
{
    return 0;
}

static void set_parser_filter(struct trace_reader_conf *conf, trace_parser_t *parser)
{
    filter_t *filter = new_filter_t(); /* base */
    filter->type = TRACE_MATCHER_SEVERITY_LEVEL;
    filter->u.severity = ((conf->severity_level < TRACE_SEV__MIN ||
                           conf->severity_level > TRACE_SEV__MAX) ?
                          TRACE_SEV_INFO : (conf->severity_level)) ;

#define WITH(FILTER) if (conf->FILTER) and_filter(filter, conf->FILTER)
    WITH(filter_time);
    WITH(filter_grep);
    WITH(filter_strcmp);
    WITH(filter_value);
    WITH(filter_value2);
    WITH(filter_value3);
    WITH(filter_fuzzy);
    WITH(filter_function);
    WITH(filter_quota);         /* must be last for lazy evaluation */
#undef  WITH

    memcpy(&parser->record_filter, filter, sizeof(parser->record_filter));
}

static void set_parser_params(struct trace_reader_conf *conf, trace_parser_t *parser)
{
    set_parser_filter(conf, parser);
    parser->nanoseconds_ts     = conf->nanoseconds_ts;
    parser->show_timestamp     = ! conf->empty_timestamp;
    parser->color              = ! conf->no_color;
    parser->indent             = conf->severity_level <= TRACE_SEV_FUNC_TRACE;
    parser->show_field_names   = conf->show_field_names;
    parser->show_function_name = ! conf->hide_funtion_name; 
    parser->compact_traces     = conf->compact_trace;
    parser->always_hex         = conf->hex;
    parser->after_count        = conf->after_count;
    parser->free_dead_buffer_contexts = conf->free_dead_process_metadata;
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
        parser.show_filename = conf->show_trace_file ? filename : 0;

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
    int rc = parse_command_line(&conf, argc, argv);
    if (0 != rc)
    	exit_usage(argv[0], NULL);

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
        exit_usage(argv[0], "Invalid paramter");

    default:
        break;
    }
    
    return 0;
}
