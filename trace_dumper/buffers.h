/*
 * buffers.h
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

#ifndef BUFFERS_H_
#define BUFFERS_H_

#include "../list_template.h"

int attach_and_map_buffers(struct trace_dumper_configuration_s *conf);
int map_new_buffers(struct trace_dumper_configuration_s *conf);
int unmap_discarded_buffers(struct trace_dumper_configuration_s *conf);
void discard_buffer(struct trace_dumper_configuration_s *conf, struct trace_mapped_buffer *mapped_buffer);
void discard_all_buffers_immediately(struct trace_dumper_configuration_s *conf);
void clear_mapped_records(struct trace_dumper_configuration_s *conf);
bool_t has_mapped_buffers(const struct trace_dumper_configuration_s *conf);
void add_buffer_filter(struct trace_dumper_configuration_s *conf, char *buffer_name);



#define for_each_mapped_buffer(_i_, _mapped_buffer_)      \
    for (({_i_ = 0; MappedBuffers__get_element_ptr(&conf->mapped_buffers, i, &_mapped_buffer_);}); _i_ < MappedBuffers__element_count(&conf->mapped_buffers); ({_i_++; MappedBuffers__get_element_ptr(&conf->mapped_buffers, i, &_mapped_buffer_);}))


#define for_each_mapped_records(_i_, _rid_, _mapped_buffer_, _mr_)      \
    for (({_i_ = 0; MappedBuffers__get_element_ptr(&conf->mapped_buffers, i, &_mapped_buffer_);}); _i_ < MappedBuffers__element_count(&conf->mapped_buffers); ({_i_++; MappedBuffers__get_element_ptr(&conf->mapped_buffers, i, &_mapped_buffer_);})) \
        for (({_rid_ = 0; _mr_ = &_mapped_buffer_->mapped_records[_rid_];}); _rid_ < TRACE_BUFFER_NUM_RECORDS; ({_rid_++; _mr_ = &_mapped_buffer_->mapped_records[_rid_];}))



#endif /* BUFFERS_H_ */
