/*
 * out_fd.h
 * A simple, low-level data structure for storing rendered text for later output.
 *
 *  Created on: Mar 14, 2013
 *  	File created by: Yitzik Casapu of Infindiat
 *      Original author: Josef Ezra of Infinidat
 *      Maintainer:		Yitzik Casapu of Infindiat
 */

#ifndef OUT_BUF_H_
#define OUT_BUF_H_


#ifdef __cplusplus
extern "C" {
#endif

#include "bool.h"

typedef struct out_fd {
    char buf[0x4000];
    unsigned int i;
} out_fd_t;

void out_init(struct out_fd* out);
void out_flush(struct out_fd* out);
void out_check(out_fd_t* out);

static inline void SAY_C(out_fd_t* out, const char chr) {
    out->buf[out->i++] = chr;
}
void SAY_S(out_fd_t* out, const char* str);
void SAY_ESCAPED_S(out_fd_t* out, const char* buf, size_t size);
void SAY_F(out_fd_t* out, const char* fmt, ...);
void SAY_INT(out_fd_t* out, bool_t color_bool, bool_t force_hex, unsigned flags, unsigned value);
void SAY_FLOAT(out_fd_t* out, bool_t color_bool, double value);

#define SAY_COL(O,C) do { if (color_bool) { SAY_S(O,C); } } while (0)
#define SAY_COLORED(O,S,C) do { if (color_bool) { SAY_COL(O,C); SAY_S(O,S); SAY_COL(O,ANSI_RESET);} else { SAY_S(O,S); } } while(0)

#ifdef __cplusplus
}
#endif

#endif /* OUT_BUF_H_ */
