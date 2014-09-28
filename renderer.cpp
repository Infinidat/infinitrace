/*
 * renderer.cpp
 *
 *  Created on: Feb 27, 2013
 *      Author: yitzikc
 */

#include "platform.h"

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <sysexits.h>
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>

#include "min_max.h"
#include "array_length.h"
#include "trace_defs.h"
#include "list_template.h"
#include "trace_metadata_util.h"
#include "object_pool.h"
#include "trace_sev_display.h"
#include "string.h"
#include "timeformat.h"
#include "trace_str_util.h"
#include "hashmap.h"
#include "parser_internal.h"
#include "filter.h"
#include "renderer.h"




void out_init(struct out_fd* out) {
    out->i = 0;
}

void out_flush(struct out_fd* out) {
#define _outout stdout
    fwrite(out->buf, 1, out->i, _outout);
    out_init(out);
#undef _outout
}

static inline int out_capacity(const out_fd_t* out)
{
	return sizeof(out->buf) - out->i;
}

static void out_check(out_fd_t* out) {
    if (out_capacity(out) > 0x200)
        return;
    fprintf(stderr, "Formatted record is too long (0x%x)", out->i);
    out_flush(out);
    /* exit(EX_DATAERR); */
}

static void SAY_S(out_fd_t* out, const char* str) {
    out_check(out);
    char* dst = out->buf + out->i;
    out->i += trace_strncpy(dst, str, out_capacity(out));
}
static inline void SAY_C(out_fd_t* out, const char chr) {
    out->buf[out->i++] = chr;
}
static void SAY_F(out_fd_t* out, const char* fmt, ...) {
    out_check(out);
    va_list args;
    va_start(args, fmt);
    const int capacity = out_capacity(out);
    const int rc = vsnprintf(out->buf + out->i, capacity, fmt, args);
    va_end(args);
    if (rc >= capacity) {  // Could not accommodate the output string
    	out->i += capacity - 1;
    	out_check(out);
    }
    else {
    	out->i += rc;
    }
}

#define SAY_COL(O,C) do { if (color_bool) { SAY_S(O,C); } } while (0)
#define SAY_COLORED(O,S,C) do { if (color_bool) { SAY_COL(O,C); SAY_S(O,S); SAY_COL(O,ANSI_RESET);} else { SAY_S(O,S); } } while(0)

static inline void SAY_ESCAPED_C(out_fd_t* out, char chr) {
    static const char hex_digits[] = "0123456789abcdef";

    if (isprint(chr)) {
        SAY_C(out, chr);
    }
    else {
        SAY_C(out, '\\');
        switch (chr) {
        case '\n': SAY_C(out, 'n'); break;
        case '\t': SAY_C(out, 't'); break;
        case '\r': SAY_C(out, 'r'); break;
        case '\0': SAY_C(out, '0'); break;
        default:
            SAY_C(out, 'x');
            SAY_C(out, hex_digits[(chr >> 4) & 0xf]);
            SAY_C(out, hex_digits[ chr       & 0xf]);
            break;
        }
    }
}

static void SAY_ESCAPED_S(out_fd_t* out, const char* buf, size_t size) {
    out_check(out);
    for (size_t i = 0; i < size; i++) {
        SAY_ESCAPED_C(out, buf[i]);
    }
}

static void SAY_INT(out_fd_t* out, bool_t color_bool, bool_t force_hex, unsigned flags, unsigned value) {
    SAY_COL(out, CYAN_B);
    const bool_t hex = force_hex || (flags & TRACE_PARAM_FLAG_HEX);
    SAY_F  (out, hex ? "0x%x" : (flags & TRACE_PARAM_FLAG_UNSIGNED) ? "%u" : "%d", value);
    SAY_COL(out, ANSI_RESET);
}

static void SAY_FLOAT(out_fd_t* out, bool_t color_bool, double value) {
    SAY_COL(out, CYAN_B);
    SAY_F  (out, "%f", value);
    SAY_COL(out, ANSI_RESET);
}

static int ends_with_equal(const out_fd_t* out) {
    return (out->i > 1 && out->buf[out->i-1] == '=');
}



static const char* get_type_name(const struct trace_parser_buffer_context *context, const char *type_name, unsigned int value)
{
    any_t ptr ;

    /* Note: hashmap_get silently circumvents the const-ness of context, but we do this carefully  */
    int rc = hashmap_get(context->type_hash, type_name, &ptr);
    if (rc != MAP_OK)
        return NULL;

    struct trace_type_definition_mapped* type = any_t2p<trace_type_definition_mapped>(ptr);

    if (type->map == 0) {
        type->map = hashmap_new();
        if (0 != type->map) {
            for (int i = 0; NULL !=  type->def->enum_values[i].name; i++) {
                rc = hashmap_put_int(type->map,
                                     type->def->enum_values[i].value,
                                     static_cast<any_t>(type->def->enum_values[i].name));
                if (MAP_OK != rc) {
                    break;
                }
            }
        }
        else {
            rc = MAP_OMEM;
        }

        if (MAP_OMEM == rc) {
            errno = ENOMEM;
            hashmap_free(type->map);
            type->map = 0;
        }
    }

    if (rc == MAP_OK)
        rc = hashmap_get_int(type->map, value, &ptr);

    if (rc != MAP_OK)
        return NULL;

    return static_cast<const char*>(ptr);
}

int TRACE_PARSER__render_typed_params_flat(
        const trace_parser_t *parser,
        const struct trace_parser_buffer_context *context,
        const struct trace_record_typed *typed_record,
        int *bytes_processed,   /* Output parameter. A negative value signals an error */
        out_fd_t* out,
        bool_t describe_params)
{
    unsigned int metadata_index = typed_record->log_id;
    const unsigned char *pdata = typed_record->payload;
    const struct trace_log_descriptor *log_desc;
    const struct trace_param_descriptor *param;
    const int color_bool = parser->color;

    if (metadata_index >= context->metadata->log_descriptor_count) {
        SAY_COL(out, RED_B);
        SAY_F(out, "<<< Invalid Metadata %d >>>", metadata_index);
        SAY_COL(out, ANSI_RESET);

        *bytes_processed = -1;
        errno = EILSEQ;
        return out->i;
    }

    log_desc = get_log_descriptor(context, metadata_index);

    enum trace_log_descriptor_kind trace_kind = log_desc->kind;
    const char *delimiter = trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY ? ", " : " ";
    int first = 1;
    for (param = log_desc->params; (param->flags != 0); param++) {
        int put_delimiter = 1; // (param + 1)->flags != 0 ;

        if (first) {
            if      (trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY)
                SAY_S  (out, "--> ");
            else if (trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_LEAVE)
                SAY_S  (out, "<-- ");
        }

        if ((param->flags & TRACE_PARAM_FLAG_NAMED_PARAM) &&
            (trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY || parser->field_disp) &&
             param->param_name[0]) {
                SAY_COL(out, WHITE_B);
                SAY_S  (out, param->param_name);
                SAY_S  (out, "=");
        }

        switch (param->flags &
                (TRACE_PARAM_FLAG_ENUM    |
                 TRACE_PARAM_FLAG_NUM_8   |
                 TRACE_PARAM_FLAG_NUM_16  |
                 TRACE_PARAM_FLAG_NUM_32  |
                 TRACE_PARAM_FLAG_NUM_64  |
                 TRACE_PARAM_FLAG_NUM_FLOAT	 |
                 TRACE_PARAM_FLAG_CSTR    |
                 TRACE_PARAM_FLAG_VARRAY  |
                 TRACE_PARAM_FLAG_NESTED_LOG)) {

        case TRACE_PARAM_FLAG_NESTED_LOG: {
            if (describe_params) {
                SAY_COL(out, WHITE_B);
                SAY_F  (out, "{<%s>}", param->type_name);
                SAY_COL(out, ANSI_RESET);
            }
            else {
                SAY_COL(out, WHITE_B);
                SAY_S  (out, "{ ");
                SAY_COL(out, ANSI_RESET); /* before __REPR__'s const string */
                int _bytes_processed = 0;
                TRACE_PARSER__render_typed_params_flat(parser, context, reinterpret_cast<const struct trace_record_typed *>(pdata), &_bytes_processed, out, FALSE);
                if (_bytes_processed <= 0) {
                    *bytes_processed = -1;
                    break;
                }
                pdata += _bytes_processed;
                SAY_COL(out, WHITE_B);
                SAY_S  (out, " }");
            }
        } break;

        case TRACE_PARAM_FLAG_CSTR: {
            if (param->const_str) {
                if (((trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY) ||
                     (trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_LEAVE)) && first) {

                    SAY_COL(out, YELLOW_B);
                    SAY_S  (out, param->const_str);
                    SAY_COL(out, ANSI_RESET);
                    SAY_C  (out, '(');
                    first = 0;
                    if ((param + 1)->flags == 0)
                        SAY_C  (out, ')');
                    continue;
                }
                else {
                    SAY_S  (out, param->const_str);
                    if (ends_with_equal(out))
                        put_delimiter = 0;
                }
            }
            else
                SAY_S  (out, "<cstr?>");
        } break;

        case TRACE_PARAM_FLAG_VARRAY: {
            if (describe_params) {
                SAY_COLORED(out, "<vstr>", CYAN_B);
            }
            else {
                if (param->flags & TRACE_PARAM_FLAG_STR) {
                    SAY_COL(out, CYAN_B);
                    SAY_C  (out, '\"');
                }

                unsigned char continuation = FALSE;
                do {
                    unsigned char sl = (*pdata);
                    const unsigned char CONTINUATION_MASK = 0x80;
                    const unsigned char LENGTH_MASK = CONTINUATION_MASK - 1;

                    unsigned char len = sl & LENGTH_MASK;
                    continuation =      sl & CONTINUATION_MASK;
                    pdata ++;
                    if (param->flags & TRACE_PARAM_FLAG_STR) {
                        SAY_COL(out, CYAN_B);
                        SAY_ESCAPED_S(out, reinterpret_cast<const char *>(pdata), len);
                    }
                    pdata += len;

                } while (continuation);

                if (param->flags & TRACE_PARAM_FLAG_STR) {
                    SAY_C  (out, '\"');
                    SAY_COL(out, ANSI_RESET);
                }
            }
        } break;

            /* integer data */
#define GET_PDATA_VAL(TYPE) const TYPE _val = (*reinterpret_cast<const TYPE*>(pdata)); pdata += sizeof(_val)

#define SHOW_DESCR_IF_NECESSARY(TYPE)					\
		if (describe_params) {                          \
			SAY_COLORED(out, "<" #TYPE ">", CYAN_B);    \
		}                                               \

#define DISPLAY_INT(TYPE)                               \
        do SHOW_DESCR_IF_NECESSARY(TYPE)				\
        else {                                          \
            GET_PDATA_VAL(unsigned TYPE);               \
            SAY_INT(out, color_bool, parser->always_hex, param->flags, _val); \
        } while(0)

#define DISPLAY_FLOAT(TYPE)			\
        do SHOW_DESCR_IF_NECESSARY(TYPE)				\
        else {                                          \
            GET_PDATA_VAL(TYPE);               \
            SAY_FLOAT(out, color_bool, _val); \
        } while(0)

        case TRACE_PARAM_FLAG_ENUM: {
            if (describe_params) {
                SAY_COL(out, CYAN_B);
                SAY_F  (out, "<%s>", param->type_name);
                SAY_COL(out, ANSI_RESET);
            }
            else {
                GET_PDATA_VAL(unsigned int);
                const char* name = get_type_name(context, param->type_name, _val);
                SAY_COL(out, BLUE_B);
                if (name)
                    SAY_S  (out, name);
                else
                    SAY_F  (out, "<enum:%d>", _val);
            }
        } break;

        case TRACE_PARAM_FLAG_NUM_8:
            DISPLAY_INT(char);
            break;

        case TRACE_PARAM_FLAG_NUM_16:
            DISPLAY_INT(short);
            break;

        case TRACE_PARAM_FLAG_NUM_32:
            DISPLAY_INT(int);
            break;

        case TRACE_PARAM_FLAG_NUM_32 | TRACE_PARAM_FLAG_NUM_FLOAT:
			DISPLAY_FLOAT(float);
			break;

        case TRACE_PARAM_FLAG_NUM_64 | TRACE_PARAM_FLAG_NUM_FLOAT:
			DISPLAY_FLOAT(double);
			break;

        case TRACE_PARAM_FLAG_NUM_64: {
        	SHOW_DESCR_IF_NECESSARY(long long)
            else {
                const bool_t hex_bool = (param->flags & TRACE_PARAM_FLAG_HEX) || parser->always_hex;
                GET_PDATA_VAL(unsigned long long);
                SAY_COL(out, CYAN_B);
                SAY_F  (out, ( hex_bool ? "0x%llx" : (param->flags & TRACE_PARAM_FLAG_UNSIGNED) ? "%llu" : "%lld" ), _val);
            }
        } break;

        default: break;
        }

        if ((param + 1)->flags == 0 && (trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY ||
                                        trace_kind == TRACE_LOG_DESCRIPTOR_KIND_FUNC_LEAVE)) {
            SAY_COL(out, ANSI_RESET);
            SAY_S  (out, ")");
        }

        if ( put_delimiter) {
            SAY_COL(out, ANSI_RESET);
            SAY_S  (out, delimiter);
        }
    }

    if (parser->show_function_name &&
        log_desc->function &&
        log_desc->function[0] ) {
        SAY_COL(out, WHITE_B);
        SAY_C  (out, ' ');
        SAY_C  (out, '<');
        SAY_S  (out, log_desc->function);

        if (describe_params) {
            SAY_F(out, "() %s:%u", log_desc->file, log_desc->line);
        }

        SAY_C  (out, '>');
    }
    SAY_COL(out, ANSI_RESET);
    (*bytes_processed) = pdata - reinterpret_cast<const unsigned char *>(typed_record);
    return out->i; // total_length;
}

#undef DISPLAY_INT
#undef DISPLAY_FLOAT
#undef SHOW_DESCR_IF_NECESSARY
#undef GET_PDATA_VAL

static const char * severity_to_str(unsigned int sev, int color_bool) {

    static const char* sevs_colored[] = {
        GREY     "----",

#define TRACE_SEV_X(ignored, name) TRACE_SEV_##name##_DISPLAY_COLOR TRACE_SEV_##name##_DISPLAY_STR,

        TRACE_SEVERITY_DEF

#undef TRACE_SEV_X

    };
    static const char* sevs[] = {
        "----",
#define TRACE_SEV_X(ignored, name) TRACE_SEV_##name##_DISPLAY_STR,

        TRACE_SEVERITY_DEF

#undef TRACE_SEV_X

    };

    enum trace_severity mapped_sev = trace_sev_mapping[sev];
    return
        (mapped_sev < TRACE_SEV_FUNC_TRACE || mapped_sev > TRACE_SEV__MAX ) ?
        "???" :
        color_bool ?
        sevs_colored[mapped_sev - TRACE_SEV_FUNC_TRACE] :
        sevs        [mapped_sev - TRACE_SEV_FUNC_TRACE] ;
}

int TRACE_PARSER__format_typed_record(
        const trace_parser_t *parser,
        const struct trace_parser_buffer_context *context,
        const struct trace_record *record,
        out_fd_t* out )
{

    const int color_bool = parser->color;
    const int timestamp_bool = parser->show_timestamp;
    SAY_COL(out, ANSI_RESET);
    if (timestamp_bool) {
        SAY_S  (out, format_timestamp(record->ts, parser->nanoseconds_ts, parser->compact_traces));

        SAY_S  (out, " [");
        SAY_COL(out, MAGENTA);

        if (parser->compact_traces)
            SAY_F  (out, "%5d", record->pid);
        else
            SAY_S  (out, context ? context->name : "<? unknown>");
        SAY_COL(out, GREY);
        SAY_S  (out, ":");
    }
    else {
        SAY_S  (out, "[");
        SAY_COL(out, MAGENTA);
    }

    if (parser->show_pid && !parser->compact_traces) {
        SAY_COL(out, MAGENTA);
        SAY_F  (out, "%5d", record->pid);
        SAY_COL(out, ANSI_RESET);
        SAY_S  (out, ":");
    }

    SAY_COL(out, BLUE_B);
    SAY_F  (out, "%5d", record->tid);
    SAY_COL(out, ANSI_RESET);
    SAY_S  (out, "] ");

    SAY_S  (out, severity_to_str(record->severity, color_bool));
    // SAY_COL(out, ANSI_RESET);
    SAY_S  (out, ": ");

    /*
    if (parser->indent)
        for (int i = 4*MAX(record->nesting, 0); i; i--)
            SAY_C  (out, ' ');
    */

    int bytes_processed = 0;
    if (context) {
        TRACE_PARSER__render_typed_params(parser, context, &record->u.typed, &bytes_processed, out, FALSE);
    }
    else
        SAY_COLORED(out, "<?>", RED_B);

    SAY_COL(out, ANSI_RESET);
    SAY_C  (out, '\n');

    if (bytes_processed <= 0) {
        return -1;
    }
    return out->i; // total_length;
}


static int get_minimal_log_id_size(const struct trace_parser_buffer_context *context, trace_log_id_t log_id, bool_t *exact_size)
{
    const struct trace_log_descriptor *log_desc;
    const struct trace_param_descriptor *param;
    int minimal_log_id_size = sizeof(log_id);
    if (log_id >= context->metadata->log_descriptor_count) {
        errno = EINVAL;
        return -1;
    }

    log_desc = get_log_descriptor(context, log_id);

    *exact_size = TRUE;
    for (param = log_desc->params; (param->flags != 0); param++) {
        if (param->flags & TRACE_PARAM_FLAG_NESTED_LOG) {
            minimal_log_id_size += sizeof(log_id);
            *exact_size = FALSE;
            continue;
        }

        if (param->flags & TRACE_PARAM_FLAG_VARRAY) {
            minimal_log_id_size += 1;
            *exact_size = FALSE;
            continue;
        }

        if (param->flags & TRACE_PARAM_FLAG_ENUM) {
            minimal_log_id_size += sizeof(int);
            continue;
        }

        if (param->flags & TRACE_PARAM_FLAG_NUM_8) {
            minimal_log_id_size += sizeof(char);
            continue;
        }

        if (param->flags & TRACE_PARAM_FLAG_NUM_16) {
            minimal_log_id_size += sizeof(short);
            continue;
        }

        if (param->flags & TRACE_PARAM_FLAG_NUM_32) {
            minimal_log_id_size += sizeof(int);
            continue;
        }

        if (param->flags & TRACE_PARAM_FLAG_NUM_64) {
            minimal_log_id_size += sizeof(long long);
            continue;
        }
    }

    return minimal_log_id_size;
}

static bool_t validate_sizes(bool_t exact_size, unsigned avg_size, unsigned minimal_log_size)
{
    if (exact_size) {
        const unsigned expected_phys_recs = (minimal_log_size + TRACE_RECORD_PAYLOAD_SIZE - 1) / TRACE_RECORD_PAYLOAD_SIZE;
        return expected_phys_recs * TRACE_RECORD_SIZE == avg_size;
    }
    else {
        return avg_size >= minimal_log_size;
    }
}

int log_id_format_sizes(struct trace_parser_buffer_context *context, trace_log_id_t log_id, int avg_size, log_id_size_info_output_buf_t size_info)
{
    bool_t exact_size = FALSE;
    unsigned int minimal_log_size = get_minimal_log_id_size(context, log_id, &exact_size);
    const char *const exact_indicator = exact_size ? "*" : "";

    unsigned pos = sprintf(size_info, "<%03d%-1s", minimal_log_size, exact_indicator);
    if (avg_size >= 0) {
        assert(validate_sizes(exact_size, avg_size, minimal_log_size));
        pos += sprintf(size_info + pos, "/%4d", avg_size);
    }
    pos += sprintf(size_info + pos, ">");
    assert(pos < sizeof(log_id_size_info_output_buf_t));

    return pos;
}

int log_id_to_log_template(struct trace_parser *parser, struct trace_parser_buffer_context *context, int log_id, char *formatted_record, int formatted_record_size)
{
    int total_length = 0;
    formatted_record[0] = '\0';

#define APPEND_FORMATTED_TEXT(...) do {                                   \
        int _len_ = snprintf(&formatted_record[total_length],             \
                             formatted_record_size - total_length - 1,    \
                             __VA_ARGS__);                                \
        if (_len_ < 0 || _len_ >= formatted_record_size - total_length - 1) { errno = ENOMEM; return -1; } \
        total_length += _len_;                                            \
    } while (0);


    const struct trace_log_descriptor *descriptor = NULL;
    if (parser->file_info.format_version >= TRACE_FORMAT_VERSION_INTRODUCED_FILE_FUNCTION_METADATA) {
        descriptor = get_log_descriptor(context, log_id);
        const char *severity_str = severity_to_str(descriptor->severity, parser->color);
        APPEND_FORMATTED_TEXT("%s ", severity_str);
    }

#undef APPEND_FORMATTED_TEXT

    struct trace_record_typed record;
    record.log_id = log_id;
    int bytes_processed = 0;


    struct out_fd out;
    out_init(&out);
    int ret = TRACE_PARSER__render_typed_params(parser, context, &record, &bytes_processed, &out, TRUE);
    if (ret < 0) {
        formatted_record[0] = '\0';
        return -1;
    }
    if (total_length + static_cast<int>(out.i) >= formatted_record_size) {
        formatted_record[0] = '\0';
        errno = ENOMEM;
        return -1;
    }
    formatted_record += total_length;
    memcpy (formatted_record, out.buf, out.i);
    formatted_record[out.i] = '\0';
    return (bytes_processed > 0) ? out.i : -1;
}

void say_new_file(struct out_fd* out, trace_parser_t *parser, trace_ts_t ts) {
    const int color_bool = parser->color;
    SAY_COL(out, ANSI_RESET);
    if (parser->show_timestamp && ts) {
        SAY_S  (out, format_timestamp(MAX(ts, 0ULL), parser->nanoseconds_ts, parser->compact_traces));
        SAY_C  (out, ' ');
    }

    SAY_C  (out, '[');
    SAY_COL(out, BLUE_B);
    SAY_S  (out, "Traces New Filename");
    SAY_COL(out, ANSI_RESET);
    SAY_S  (out, "] ");
    SAY_COL(out, WHITE_B);
    SAY_S  (out, parser->show_filename);
    SAY_COL(out, ANSI_RESET);
    SAY_S  (out, "\n");
    parser->show_filename = NULL;
}


