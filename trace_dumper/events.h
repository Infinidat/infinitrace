/*
 * events.h:  Routines handling events that occur during the operation of the dumper.
 *
 *      File Created on: Jul 3, 2013 by Yitzik Casapu, Infinidat
 *      Author:          Yitzik Casapu, Infinidat
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


#ifndef EVENTS_H_
#define EVENTS_H_

union trace_event_details {
    const char *filename;
    int sig_num;
    void *other;
};

typedef union trace_event_details trace_event_details_t;

enum trace_event {
    TRACE_FILE_CLOSED = 1,
};

int trace_send_event(enum trace_event evt_code, trace_event_details_t *details);

#endif /* EVENTS_H_ */
