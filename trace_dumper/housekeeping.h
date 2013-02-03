/*
 * housekeeping.h:  Routines run periodically for dumper maintenance and diagnostic output.
 *
 *      File Created on: Feb 3, 2013 by Yitzik Casapu, Infinidat
 *      Original Author: Yotam Rubin, 2012
 *      Maintainer:      Yitzik Casapu, Infinidat
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

#ifndef HOUSEKEEPING_H_
#define HOUSEKEEPING_H_

/* Periodic housekeeping functions: Look for any processes that have started and need to have their traces collected, or that have ended, allowing any resouces
 * allocating for serving them to be freed.
 * Return value:
 * 0        - If housekeeping was performed successfully
 * EAGAIN   - If the function was called prematurely and no housekeeping was done
 * < 0      - If an error occurred.
 *  */
int do_housekeeping_if_necessary(struct trace_dumper_configuration_s *conf);

/* Periodic online statistics */
void dump_online_statistics(const struct trace_dumper_configuration_s *conf);
void possibly_dump_online_statistics(struct trace_dumper_configuration_s *conf);

#endif /* HOUSEKEEPING_H_ */
