/***
   copyright 2012 Josef Ezra <jezra@infinidat>

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
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include "timeformat.h"

static int is_digit(char chr) {
    return chr >= '0' && chr <= '9' ;
}

static int all_digits(const char* str) {
    if (! (str && *str) )
        return 0;
    for (;*str; str++)
        if ( ! is_digit(*str))
            return 0;
    return 1;
}

static int pow10i(int n){
    return n>0 ? 10*pow10i(n-1) : 1;
}

static long long atoll_n(const char* str, int n) {
    long long ret = 0;
    for (int i = n ; i; i -- ) {
        if (! is_digit(str[n-i]))
            return ret;
        ret += (str[n-i] - '0') * pow10i(i-1);
    }
    return ret;
}

#if defined(_BSD_SOURCE) || defined(_SVID_SOURCE)
/* we have timegm() */
#else
/* poor man's timegm(): */
time_t timegm(struct tm *tm)
{
    time_t ret;
    char *tz;

    tz = getenv("TZ");
    setenv("TZ", "", 1);
    tzset();
    ret = mktime(tm);
    if (tz) {
        setenv("TZ", tz, 1);
    } else {
        unsetenv("TZ");
    }
    tzset();
    return ret;
}
#endif

#define SECOND (1000000000LL)

unsigned long long str_to_nano_seconds(const char* str) {
    /* possible formats:
       nnnnnn - micro timer
       nnnn/nn/nn aa:aa:aa nnnnn - timestamp timer
       aa:aa:aa nnnnn - omit date
       part of the last two - assume zeros
     */
    int len;
    if (!str) return 0;
#define NEXT_DIGIT while (*str && !is_digit(*str)) str++ ; len = strlen(str)
    NEXT_DIGIT;
    /* 000000211630 */
    if (len > 9 && all_digits(str)) {
        return atoll(str);
    }
    struct tm t = { 0 };

    /* 2012/09/03 05:10:56 674869660 */

    /* date? */
    if (len >= 10 && str[4] == '/' && str[7] == '/') {
        t.tm_year = atoll_n(str+0, 4) - 1900;
        t.tm_mon  = atoll_n(str+5, 2) - 1;
        t.tm_mday = atoll_n(str+8, 2);
        str += 10;
        NEXT_DIGIT;
    }
    if (len >= 8 && str[2] == ':' && str[5] == ':') {
        t.tm_hour = atoll_n(str+0, 2);
        t.tm_min  = atoll_n(str+3, 2);
        t.tm_sec  = atoll_n(str+6, 2);
        str += 8;
        NEXT_DIGIT;
    }

    return (SECOND * (timegm(&t))) + atoll_n(str, 9);
}

static char cached_timestamp[100] ;
static int cached_sec_int = 0;
static unsigned long long first_ts = 0;
// static void format_timestamp(const trace_parser_t *parser, unsigned long long ts)
const char* format_timestamp(unsigned long long ts, int relative, int compact) {
    if (relative) {
        // TODO: Not really relative, is it?
        /* if( first_ts == 0) { */
        /*     first_ts = ts; */
        /*     printf("\t relative time (-r): base time is %llu\n", ts); */
        /* } */
        sprintf(cached_timestamp, "%012llu", ts - first_ts);
        return cached_timestamp;
    }
    
    time_t seconds = ts / SECOND;
    if (!compact) {
        if (cached_sec_int != seconds) {
            cached_sec_int  = seconds;
            /*
            // Homemade asctime
            static const char	wday_name[7][3] = {
                "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
            };
            static const char	mon_name[12][3] = {
                "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
            };

            const struct tm *_time = gmtime(&seconds);
            sprintf(cached_sec_str, "%.3s %.3s %2d %02d:%02d:%02d %d:",
                    wday_name[_time->tm_wday], mon_name[_time->tm_mon],
                    _time->tm_mday, _time->tm_hour, _time->tm_min ,
                    _time->tm_sec, 1900 + _time->tm_year);
            */
            const struct tm *_time = gmtime(&seconds);
            sprintf(cached_timestamp, "%04d/%02d/%02d_%02d:%02d:%02d_",
                    1900+_time->tm_year, 1+_time->tm_mon, _time->tm_mday,
                    _time->tm_hour, _time->tm_min, _time->tm_sec
                   );
        }
        // magic 20
        sprintf(cached_timestamp + 20, "%09llu", ts % SECOND);
    }
    else {
        if (cached_sec_int != seconds) {
            cached_sec_int  = seconds;
            // strftime(cached_timestamp, sizeof(cached_timestamp), "%d/%m %T", gmtime(&seconds)); 
            const struct tm *_time = gmtime(&seconds);
            sprintf(cached_timestamp, "%02d:%02d:%02d_", _time->tm_hour, _time->tm_min, _time->tm_sec);
        }
        // my_strncpy(timestamp, cached_sec_str, timestamp_size);
        sprintf(cached_timestamp + 9, "%09llu", ts % SECOND);
    }
    return cached_timestamp;
}

