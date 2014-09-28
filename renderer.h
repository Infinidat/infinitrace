/*
 * renderer.h
 *
 *  Created on: Feb 26, 2013
 *      Author: yitzikc
 *
 *      Produce a textual representation of trace records
 */

#ifndef RENDERER_H_
#define RENDERER_H_

#include "bool.h"
#include "trace_defs.h"
#include "parser.h"
#include "out_fd.h"

#ifdef __cplusplus
extern "C" {
#endif


/* Variants of the render_typed_params functions, which formats data constituting trace arguments according to a specified format */

/* A variation using the older, faster but less flexible "flat" rendering engine, which produces text directly */
int TRACE_PARSER__render_typed_params_flat(
        const struct trace_parser *parser,
        const struct trace_parser_buffer_context *context,
        const struct trace_record_typed *typed_record,
        int *bytes_processed,   /* Output parameter. A negative value signals an error */
        struct out_fd* out,
        bool_t describe_params);

/* A variation using the newer, slower but more flexible modular rendering engine, which produces text via an intermediate object representation */
int TRACE_PARSER__render_typed_params_modular(
        const struct trace_parser *parser,
        const struct trace_parser_buffer_context *context,
        const struct trace_record_typed *typed_record,
        int *bytes_processed,   /* Output parameter. A negative value signals an error */
        struct out_fd* out,
        bool_t describe_params);

static inline int TRACE_PARSER__render_typed_params(
        const struct trace_parser *parser,
        const struct trace_parser_buffer_context *context,
        const struct trace_record_typed *typed_record,
        int *bytes_processed,   /* Output parameter. A negative value signals an error */
        struct out_fd* out,
        bool_t describe_params)
{
	return
#ifdef TRACE_USE_MODULAR_RENDERING
			TRACE_PARSER__render_typed_params_modular
#else
			TRACE_PARSER__render_typed_params_flat
#endif
			(parser, context, typed_record, bytes_processed, out, describe_params);
}

int TRACE_PARSER__format_typed_record(
        const struct trace_parser *parser,
        const struct trace_parser_buffer_context *context,
        const struct trace_record *record,
        struct out_fd* out );

int log_id_to_log_template(struct trace_parser *parser, struct trace_parser_buffer_context *context, int log_id, char *formatted_record, int formatted_record_size);

typedef char log_id_size_info_output_buf_t[64];
int log_id_format_sizes(struct trace_parser_buffer_context *context, trace_log_id_t log_id, int avg_size, log_id_size_info_output_buf_t size_info);

void say_new_file(struct out_fd* out, struct trace_parser *parser, trace_ts_t ts);

#ifdef __cplusplus
}
#endif /* #ifdef __cplusplus */


#endif /* RENDERER_H_ */
