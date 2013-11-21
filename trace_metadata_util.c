/***
Copyright 2012 Yotam Rubin <yotamrubin@gmail.com>
   Sponsored by infinidat (http://infinidat.com)
   
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
***/

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/mman.h>
#include "trace_defs.h"
#include "trace_lib.h"
#include "file_naming.h"
#include "array_length.h"
#include "trace_metadata_util.h"


/* Functions for relocating metadata, allocating space as needed and fixing-up pointers  */

static int relocate_ptr(unsigned long long original_base_address, unsigned long long new_base_address, unsigned long long *ptr)
{
    (*ptr) -= original_base_address;
    (*ptr) += new_base_address;

    return 0;
}

static void relocate_descriptor_parameters(const void *old_base, const void *new_base, const struct trace_log_descriptor *descriptor)
{
    const struct trace_param_descriptor *param;
    param = descriptor->params;

    while (param->flags != 0) {

        if (param->str) {
            relocate_ptr((unsigned long long) old_base, (unsigned long long) new_base, (unsigned long long *) &param->str);
        }

        if (param->param_name) {
            relocate_ptr((unsigned long long) old_base, (unsigned long long) new_base, (unsigned long long *) &param->param_name);
        }

        param++;
    }
}

static void relocate_type_definition_params(const void *old_base, const void *new_base, const struct trace_type_definition *type)
{
    struct trace_enum_value *param;
    param = type->enum_values;
    while (param->name != NULL) {
        relocate_ptr((unsigned long long) old_base, (unsigned long long) new_base, (unsigned long long *) &param->name);
        param++;
    }
}

size_t get_log_descriptor_size(unsigned fmt_version)
{
	return (fmt_version < TRACE_FORMAT_VERSION_INTRODUCED_FILE_FUNCTION_METADATA) ? 16 : sizeof(struct trace_log_descriptor);
}

void relocate_metadata(const void *original_base_address, const void *new_base_address, char *data, unsigned int descriptor_count, unsigned int type_count)
{
	relocate_metadata_for_fmt_version(original_base_address,new_base_address, data, descriptor_count, type_count, TRACE_FORMAT_VERSION);
}

void relocate_metadata_for_fmt_version(
		const void *original_base_address,
		const void *new_base_address,
		char *data,
		unsigned int descriptor_count,
		unsigned int type_count,
		unsigned int fmt_version)
{
    unsigned int i;

    assert(sizeof(unsigned long long) >= sizeof(void *));

    size_t log_descriptor_size = get_log_descriptor_size(fmt_version);
    struct trace_type_definition *type_definitions = (struct trace_type_definition *) (data + log_descriptor_size * descriptor_count);

    for (i = 0; i < descriptor_count; i++) {
    	struct trace_log_descriptor *log_descr = (struct trace_log_descriptor *) (data + log_descriptor_size * i);
        relocate_ptr((unsigned long long)original_base_address, (unsigned long long)new_base_address, (unsigned long long *) &log_descr->params);
        if (fmt_version >= TRACE_FORMAT_VERSION_INTRODUCED_FILE_FUNCTION_METADATA) {
        	relocate_ptr((unsigned long long)original_base_address, (unsigned long long)new_base_address, (unsigned long long *) &log_descr->file);
        	relocate_ptr((unsigned long long)original_base_address, (unsigned long long)new_base_address, (unsigned long long *) &log_descr->function);
        }
        relocate_descriptor_parameters(original_base_address, new_base_address, log_descr);
    }

    for (i = 0; i < type_count; i++) {
        relocate_ptr((unsigned long long)original_base_address, (unsigned long long)new_base_address, (unsigned long long *) &type_definitions[i].type_name);
        relocate_ptr((unsigned long long)original_base_address, (unsigned long long)new_base_address, (unsigned long long *) &type_definitions[i].params);
        relocate_type_definition_params(original_base_address, new_base_address, &type_definitions[i]);
    }
}


