/*
 * parser_mmap.h
 *
 *
 * Routines for creating and applying memory mappings of file data - either directly to binary files or to temporary
 * anonymous memory mappings containing data extraced via zlib.
 *
 *  Created on:   Jan 14, 2013 by Yitzik Casapu, Infinidat
 *  Copyright by  Infinidat (http://infinidat.com)
 *  Contributors: Josef Ezra, Yitzik Casapu and others of Infinidat
 *                Yotam Rubin
 *  Maintainer:   Yitzik Casapu, Infinidat
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

#ifndef _TRACE_PARSER_MMAP_H_
#define _TRACE_PARSER_MMAP_H_

struct trace_parser;   /* Defined in parser.h */

/* Open the file whose name is given by filename and make its content available inside a memory-mapped address range,
 * uncompressing it via zlib if necessary */
int trace_parser_mmap_file(struct trace_parser *parser, const char *filename);

/* Unmap the memory for the parser object, close the file descriptor as well as any objects created via the inotify API related to it. */
void trace_parser_unmap_file(struct trace_parser *parser);

/* Refresh the end offset of the parser's file and if necessary increase the size of the corresponding memory mapping */
off64_t trace_parser_update_end_offset(struct trace_parser *parser);

#endif /* _TRACE_PARSER_MMAP_H_ */
