/*
 * open_close.h
 *
 *  Created on: Aug 9, 2012
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

#ifndef OPEN_CLOSE_H_
#define OPEN_CLOSE_H_

#include "../bool.h"
#include "trace_dumper.h"

int rotate_trace_file_if_necessary(struct trace_dumper_configuration_s *conf);
int open_trace_file_if_necessary(struct trace_dumper_configuration_s *conf);
bool_t trace_quota_is_enabled(const struct trace_dumper_configuration_s *conf);
unsigned long long trace_get_walltime(void);
void close_record_file_if_necessary(struct trace_dumper_configuration_s *conf);
void close_record_file(struct trace_dumper_configuration_s *conf);

#endif /* OPEN_CLOSE_H_ */
