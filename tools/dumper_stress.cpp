#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include "common/traces/trace_defs.h"
#include "common/traces/trace_user.h"

const int  n_threads = 64;
const int  n_thread_iters = 200000;
const long interval_ns = 1;
const bool yield_cpu = false;

enum { INT_ARRAY_LEN = 10 };

inline static void fill_int_arr(int arr[], int start)
{
	for (int i = 0; i < INT_ARRAY_LEN; i++) {
		arr[i] = start + i;
	}
}

class container {
public:
	int b;
	int arr[INT_ARRAY_LEN];
	void __repr__ { REPR(b, arr[0], arr[1] , arr[2], arr[3], arr[4], arr[5], arr[6], arr[7], arr[8], arr[9]); }
};

static void *do_log(void *)
{
	struct timespec interval = {0, 0};
	interval.tv_nsec = interval_ns;
	pthread_t thread = pthread_self();
	container s;

	s.b = 42;
	for (int i = 0; i < n_thread_iters; i++) {
		if (i & 0xFFF) {
			INFO(thread, ": iteration", i);
		}
		else if (i & 0xFFFF) {
			fill_int_arr(s.arr, (i + static_cast<int>(thread)) % 17);
			WARN(thread, ": iteration", i, "s=", &s);
		}
		else {
			fill_int_arr(s.arr, static_cast<int>(thread) % 1003);
			ERR(thread, ": iteration", i, "s=", &s);
		}
		if (interval_ns > 0)
			nanosleep(&interval, NULL);

		if (yield_cpu)
			sched_yield();
	}

    return 0;
}

int main(void) {
	pthread_t threads[n_threads];

	fprintf(stderr, "Running %d threads each running %d iterations with %luns intervals,%s yielding CPU\n",
			n_threads, n_thread_iters, interval_ns, yield_cpu ? "" : " not");

	sleep(2);

	for(int i =  0; i < n_threads; i++) {
		pthread_create(&threads[i], 0 , do_log, 0);
	}

	for(int i =  0; i < n_threads; i++) {
		pthread_join(threads[i], 0);
	}

	sleep(1);
	return 0;
}
