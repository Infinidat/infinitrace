/*
 * opt_util.c
 *
 *  Created on: Sep 13, 2012
 *      Author: yitzikc
 */

#include <string.h>
#include "opt_util.h"

void short_opts_from_long_opts(char *short_opts, const struct option *longopts)
{
	for (; longopts->val != 0; longopts++) {
		*short_opts = longopts->val;
		short_opts++;

		unsigned n_colons = 0;
		switch (longopts->has_arg) {
		case required_argument:
			n_colons = 1;
			break;

		case optional_argument:
			n_colons = 2;
			break;

		default:
			break;
		}

		if (n_colons > 0) {
			memset(short_opts, ':', n_colons);
			short_opts += n_colons;
		}
	}

	*short_opts = '\0';
}
