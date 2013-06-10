/*
 * init.h
 *
 *  Created on: Aug 8, 2012
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

#ifndef __TRACE_DUMPER_INIT_H_
#define __TRACE_DUMPER_INIT_H_

void print_usage(const char *prog_name);
int parse_commandline(struct trace_dumper_configuration_s *conf, int argc, char **argv);
int init_dumper(struct trace_dumper_configuration_s *conf);
int set_signal_handling(void);
struct trace_dumper_configuration_s *trace_dumper_get_configuration();

#endif /* __TRACE_DUMPER_INIT_H_ */
