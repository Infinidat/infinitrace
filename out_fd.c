/*
 * out_fd.c
 *
 *  Created on: Mar 14, 2013
 *      Author: yitzikc
 */


#include <stdarg.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include "trace_defs.h"
#include "trace_sev_display.h"
#include "trace_str_util.h"
#include "out_fd.h"

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

void out_check(out_fd_t* out) {
    if (out_capacity(out) > 0x200)
        return;
    fprintf(stderr, "Formatted record is too long (0x%x)", out->i);
    out_flush(out);
    /* exit(EX_DATAERR); */
}

void SAY_S(out_fd_t* out, const char* str) {
    out_check(out);
    char* dst = out->buf + out->i;
    out->i += trace_strncpy(dst, str, out_capacity(out));
}

void SAY_F(out_fd_t* out, const char* fmt, ...) {
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

void SAY_ESCAPED_S(out_fd_t* out, const char* buf, size_t size) {
    out_check(out);
    for (size_t i = 0; i < size; i++) {
        SAY_ESCAPED_C(out, buf[i]);
    }
}

void SAY_INT(out_fd_t* out, bool_t color_bool, bool_t force_hex, unsigned flags, unsigned value) {
    SAY_COL(out, CYAN_B);
    const bool_t hex = force_hex || (flags & TRACE_PARAM_FLAG_HEX);
    SAY_F  (out, hex ? "0x%x" : (flags & TRACE_PARAM_FLAG_UNSIGNED) ? "%u" : "%d", value);
    SAY_COL(out, ANSI_RESET);
}

void SAY_FLOAT(out_fd_t* out, bool_t color_bool, double value) {
    SAY_COL(out, CYAN_B);
    SAY_F  (out, "%f", value);
    SAY_COL(out, ANSI_RESET);
}
