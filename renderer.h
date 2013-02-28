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

#ifdef __cplusplus
extern "C" {
#endif

typedef struct out_fd {
    char buf[0x4000];
    unsigned int i;
} out_fd_t;

/* Variants of the render_typed_params functions, which formats data constituting trace arguments according to a specified format */

/* A variation using the older, faster but less flexible "flat" rendering engine, which produces text directly */
int TRACE_PARSER__render_typed_params_flat(
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
#error "Trace modular rendering is not yet implemented in this version"
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

void say_new_file(struct out_fd* out, struct trace_parser *parser, trace_ts_t ts);

void out_init(struct out_fd* out);
void out_flush(struct out_fd* out);

#ifdef __cplusplus
}
#endif /* #ifdef __cplusplus */


#endif /* RENDERER_H_ */
