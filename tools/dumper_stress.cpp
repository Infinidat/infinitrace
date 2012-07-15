#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include "common/traces/trace_user.h"

const int  n_threads = 64;
const int  n_thread_iters = 200000;
const long interval_ns = 1;
const bool yield_cpu = false;

static void *do_log(void *)
{
	struct timespec interval = {0, 0};
	interval.tv_nsec = interval_ns;
	pthread_t thread = pthread_self();
	for (int i = 0; i < n_thread_iters; i++) {
		INFO(thread, ": iteration", i);
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
