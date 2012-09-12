/*
 * opt_util.h
 *
 *  Created on: Sep 13, 2012
 *      Author: yitzikc
 */

#ifndef OPT_UTIL_H_
#define OPT_UTIL_H_

#include <getopt.h>

void short_opts_from_long_opts(char *short_opts, const struct option *longopts);
#define MAX_SHORT_OPTS_LEN(N_OPTS) (3*N_OPTS + 1)

#endif /* OPT_UTIL_H_ */
