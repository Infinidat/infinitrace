/*
 * metadata.h
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

#ifndef METADATA_H_
#define METADATA_H_

#include "trace_dumper.h"

int dump_metadata_if_necessary(struct trace_dumper_configuration_s *conf, struct trace_mapped_buffer *mapped_buffer);

/* Allocate and initialize an IO vector which can be used to write the metadata using writev() */
void init_metadata_iovector(struct trace_mapped_metadata *metadata, trace_pid_t pid);

/* Free supporting data-structures in the metadata area given as argument, notably the IO vector */
void free_metadata(struct trace_mapped_metadata *metadata);

#endif /* METADATA_H_ */
