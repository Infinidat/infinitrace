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

#include "bool.h"
#include "trace_macros.h"
#include "array_length.h"
#include <string.h>
#include <errno.h>

/* These macros assume the following: 
  - listdatatype is defined to hold the name of the datatype in the list 
  - listname is defined to hold the name of list 
*/


#define CREATE_LIST_PROTOTYPE(listname, listdatatype, num_elements)     \
	typedef struct listname##_s {                                       \
	unsigned element_count;                                             \
	listdatatype elements[num_elements];                                \
} listname;                                                             \
																		\
void listname ## __##init(listname *self);                              \
void listname ## __##clear(listname *self);                             \
void listname ## __##fini(listname *self);                              \
int listname##__add_element(listname *self, listdatatype *element);     \
int listname##__from_buffer(listname *self, const void *buffer);        \
int listname##__allocate_element(listname *self); \
int listname##__get_element(const listname *self, unsigned __index, listdatatype *output_element); \
int listname##__get_element_ptr(const listname *self, unsigned __index, listdatatype **element_ptr); \
int listname##__remove_element(listname *self, unsigned __index);              \
int listname##__element_count(const listname *self);                          \
int listname##__last_element_index(const listname *self);                     \
int listname##__dequeue(listname *self, listdatatype *output_element);  \
int listname##__find_element(const listname *self, listdatatype *element);    \
bool_t listname##__insertable(const listname *self);							\
enum { listname##_NUM_ELEMENTS = (num_elements) };

#define CREATE_LIST_IMPLEMENTATION(listname, listdatatype)              \
void listname ## __##init(listname *self)                               \
{                                                                       \
	memset(self, 0, sizeof(*self));                                     \
}                                                                       \
                                                                        \
int listname##__from_buffer(listname *self, const void *buffer)         \
{                                                                       \
	const listname *const other = (const listname *) buffer;            \
	listname ## __##init(self);                                         \
	const int n = other->element_count;                                 \
	if ((n < 0) || (n > listname##_NUM_ELEMENTS)) {                     \
	    errno = (n < 0) ? EINVAL : ENOMEM;                              \
        return -1;                                                      \
	}                                                                   \
	self->element_count = n;                                            \
    memcpy(self->elements, other->elements, n * sizeof(listdatatype));  \
	return 0;                                                           \
}                                                                       \
                                                                        \
void listname ## __clear(listname *self) {                              \
	self->element_count = 0;                                            \
}                                                                       \
                                                                        \
void listname ## __##fini(listname *self)                               \
{                                                                       \
	listname ## __##init(self);                                         \
}                                                                       \
                                                                        \
int listname##__add_element(listname *self, listdatatype *element)      \
{                                                                       \
	if (listname##__allocate_element(self) < 0) {                       \
        return -1;                                                      \
	}                                                                   \
	memcpy(&self->elements[self->element_count - 1], element, sizeof(*element)); \
	return 0;                                                           \
}                                                                       \
                                                                        \
int listname##__allocate_element(listname *self)                        \
{                                                                       \
	if (listname##__element_count(self) >= listname##_NUM_ELEMENTS) {   \
	    errno = ENOMEM;                                                 \
		return -1;                                                      \
	}                                                                   \
	self->element_count++;                                              \
	return 0;                                                           \
}                                                                       \
                                                                        \
                                                                        \
int listname##__get_element(const listname *self, unsigned __index, listdatatype *output_element) \
{                                                                       \
    listdatatype *p_elem = NULL;                                        \
	if (listname##__get_element_ptr(self, __index, &p_elem) < 0) {      \
        memset(output_element, 0, sizeof(*output_element));             \
		return -1;                                                      \
	}                                                                   \
                                                                        \
	memcpy(output_element, p_elem, sizeof(*output_element));            \
	return 0;                                                           \
}                                                                       \
                                                                        \
int listname##__get_element_ptr(const listname *self, unsigned __index, listdatatype **output_element_ptr) \
{                                                                       \
	if (__index >= self->element_count) {                               \
	    *output_element_ptr = NULL;                                     \
        errno = EINVAL;                                                 \
        return -1;                                                      \
	}                                                                   \
                                                                        \
	*output_element_ptr = (listdatatype *)&self->elements[__index];         \
	return 0;                                                           \
}                                                                       \
                                                                        \
int listname##__remove_element(listname *self, unsigned __index)               \
{                                                                       \
	int size_of_moved_elements = 0;                                     \
                                                                        \
	if (__index >= (unsigned) listname##__element_count(self)) {        \
        errno = ENOENT;                                                 \
	    return -1;                                                      \
	}                                                                   \
                                                                        \
	size_of_moved_elements = sizeof(self->elements[__index]) * (self->element_count - __index - 1); \
	if (!size_of_moved_elements) { self->element_count--; return 0; } \
	memmove(&self->elements[__index], &self->elements[__index + 1], size_of_moved_elements); \
                                                                        \
	self->element_count--;                                              \
	return 0;                                                           \
                                                                        \
}                                                                       \
                                                                        \
int listname##__dequeue(listname *self, listdatatype *output_element)   \
{                                                                       \
	if (listname##__element_count(self) <= 0) {                         \
        errno = EINVAL;                                                 \
        return -1;                                                      \
	}                                                                   \
                                                                        \
	listname##__get_element(self, 0, output_element);                   \
	listname##__remove_element(self, 0);                                \
    return 0;                                                           \
}                                                                       \
                                                                        \
int listname##__element_count(const listname *self)                     \
{                                                                       \
	return self->element_count;                                         \
}                                                                       \
                                                                        \
int listname##__last_element_index(const listname *self)                \
{                                                                       \
	return (listname##__element_count(self) - 1);                       \
}                                                                       \
                                                                        \
int listname##__find_element(const listname *self, listdatatype *element)     \
{                                                                       \
	const int element_count = listname##__element_count(self);          \
	for (int i = 0; i < element_count; i++) {                           \
	    listdatatype *tmp_element = NULL;                               \
		listname##__get_element_ptr(self, i, &tmp_element);             \
		if (0 == memcmp(element, tmp_element, sizeof(*element))) {      \
			return i;                                                   \
		}                                                               \
	}                                                                   \
                                                                        \
    errno = ENOENT;                                                     \
    return -1;                                                          \
}                                                                       \
                                                                        \
bool_t listname##__insertable(const listname *self) {                         \
	return (!(listname##__element_count(self) >= listname##_NUM_ELEMENTS));        \
}
