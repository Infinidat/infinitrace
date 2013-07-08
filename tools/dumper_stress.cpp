#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>
#include <utility>
#include <getopt.h>
#include <sysexits.h>
#include "common/traces/trace_defs.h"
#include "common/traces/trace_user.h"
#include "common/traces/array_length.h"

static int  n_threads = 64;
static long n_thread_iters = 200000;
static long interval_ns = 1;
static bool yield_cpu = false;

enum { INT_ARRAY_LEN = 10 };

inline static void fill_int_arr(int arr[], int start)
{
	for (int i = 0; i < INT_ARRAY_LEN; i++) {
		arr[i] = start + i;
	}
}

template <typename T> T div2(T val) {
	DEBUG("Dividing", static_cast<double>(val), "by 2");
	return val / static_cast<T>(2);
}

template <typename T1, typename T2>
class my_pair : public std::pair<T1, T2> {
public:
	my_pair(const T1& a, const T2& b) : std::pair<T1, T2>(a, b) {}
	void __repr__ const {
		REPR("A nice pair of", static_cast<long long>(this->first), static_cast<unsigned long>(this->second));
	}
};

class container {
public:
	unsigned short b;
	int arr[INT_ARRAY_LEN];
	void __repr__ { REPR(TRACE_NAMED_INT_AS_HEX(b), arr[0], arr[1] , arr[2], arr[3], arr[4], arr[5], arr[6], arr[7], arr[8], arr[9]); }
};


static const char long_text[] = "I The Period\nIt was the best of times\nit was the worst of times\nit was the age of wisdom\nit was the age of foolishness\nit was the epoch of belief\nit was the epoch of incredulity\nit was the season of Light\nit was the season of Darkness\nit was the spring of hope\nit was the winter of despair\nwe had everything before us\nwe had nothing before us\nwe were all going direct to Heaven\nwe were all going direct the other way\nin short the period was so far like the present period that some of\nits noisiest authorities insisted on its being received for good or for\nevil in the superlative degree of comparison only\nThere were a king with a large jaw and a queen with a plain face on the\nthrone of England there were a king with a large jaw and a queen with\na fair face on the throne of France In both countries it was clearer\nthan crystal to the lords of the State preserves of loaves and fishes\nthat things in general were settled for ever\nIt was the year of Our Lord one thousand seven hundred and seventyfive\nSpiritual revelations were conceded to England at that favoured period\nas at this Mrs Southcott had recently attained her fiveandtwentieth\nblessed birthday of whom a prophetic private in the Life Guards had\nheralded the sublime appearance by announcing that arrangements were\nmade for the swallowing up of London and Westminster Even the Cocklane\nghost had been laid only a round dozen of years after rapping out its\nmessages as the spirits of this very year last past supernaturally\ndeficient in originality rapped out theirs Mere messages in the\nearthly order of events had lately come to the English Crown and People\nfrom a congress of British subjects in America which strange\nto relate have proved more important to the human race than any\ncommunications yet received through any of the chickens of the Cocklane\nbrood\nFrance less favoured on the whole as to matters spiritual than her\nsister of the shield and trident rolled with exceeding smoothness down\nhill making paper money and spending it Under the guidance of her\nChristian pastors she entertained herself besides with such humane\nachievements as sentencing a youth to have his hands cut off his tongue\ntorn out with pincers and his body burned alive because he had not\nkneeled down in the rain' to do honour to a dirty procession of monks\nwhich passed within his view at a distance of some fifty or sixty\nyards It is likely enough that rooted in the woods of France and\nNorway there were growing trees when that sufferer was put to death\nalready marked by the Woodman Fate to come down and be sawn into\nboards to make a certain movable framework with a sack and a knife in\nit terrible in history It is likely enough that in the rough outhouses\nof some tillers of the heavy lands adjacent to Paris there were\nsheltered from the weather that very day rude carts bespattered with\nrustic mire snuffed about by pigs and roosted in by poultry which\nthe Farmer Death had already set apart to be his tumbrils of\nthe Revolution But that Woodman and that Farmer though they work\nunceasingly work silently and no one heard them as they went about\nwith muffled tread the rather forasmuch as to entertain any suspicion\nthat they were awake was to be atheistical and traitorous\nIn England there was scarcely an amount of order and protection to\njustify much national boasting Daring burglaries by armed men and\nhighway robberies took place in the capital itself every night\nfamilies were publicly cautioned not to go out of town without removing\ntheir furniture to upholsterers warehouses for security the highwayman\nin the dark was a City tradesman in the light and being recognised and\nchallenged by his fellowtradesman whom he stopped in his character of\nthe Captain gallantly shot him through the head and rode away the\nmail was waylaid by seven robbers and the guard shot three dead and\n";
#define LONG_TEXT_SEV NOTE

static void *do_log(void *)
{
	struct timespec interval = {0, 0};
	interval.tv_nsec = interval_ns;
	pthread_t thread = pthread_self();
	container s;

	s.b = div2<short>(0x84);
	size_t nchars = sizeof(long_text) - 1;
	char semi_long_text[800];
	memcpy(semi_long_text, long_text, sizeof(semi_long_text));
	semi_long_text[sizeof(semi_long_text) - 1] = '\0';

	my_pair<short, int> __attribute__((unused)) p(-2, 32);
	DEBUG("Do they make", p, "?");
	DEBUG("Even with a tiger on-board", TRACE_NAMED_PARAM(Pi, 3.1415926), "and sqrt_2 is around", static_cast<float>(1.414));
	for (long i = 0; i < n_thread_iters; i++) {
		if (i & 0xFFF) {
			INFO(thread, ": iteration", i);
		}
		else if (i & 0xFFFF) {
			if ((i & 0xFFFF) <= 0x2000) {
				LONG_TEXT_SEV("Semi long text", semi_long_text);
			}
			else if ((i & 0xFFFF) <= 0x4000) {
				LONG_TEXT_SEV("Tale of 2 cities", nchars, long_text);
			}
			else {
				fill_int_arr(s.arr, (i + static_cast<int>(thread)) % 17);
				WARN(thread, ": iteration", i, s.b, s);
			}
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

	const struct trace_internal_err_info *const err_info = trace_internal_err_get_last();
	if (err_info->err_num) {
	    const trace_log_descriptor *const desc = __static_log_information_start + err_info->log_id;
	    fprintf(stderr, "Thread finished with error code %d (%s) at t=%llu in %s:%u (%s())\n",
	            err_info->err_num, strerror(err_info->err_num), err_info->ts, desc->file, desc->line, desc->function);
	}

    return 0;
}

static void fatal_signal_handler(int signal)
{
	pid_t pid = getpid();
	FATAL("Dumper stress process", pid, "was killed by", signal, strsignal(signal));
	raise(signal);
	return;
}

static void register_fatal_sig_handlers(void)
{
	static const int fatal_signals[] = { SIGABRT, SIGSEGV, SIGBUS, SIGILL };
	for (unsigned i = 0; i < ARRAY_LENGTH(fatal_signals); i++) {
		struct sigaction act;
		memset(&act, 0, sizeof(act));
		act.sa_handler = fatal_signal_handler;
		act.sa_flags = SA_RESETHAND;
		assert(0 == sigaction(fatal_signals[i], &act, NULL));
	}

	return;
}

static void print_help(char* argv0)
{
	fprintf(stderr, "Usage: \n\n"
			"%s [OPTIONS]\n"
			"   -h: help\n"
			"   -T <threads>\n"
			"   -I <iterations>\n"
			"   -S <sleep (ns)\n"
			"   -Y: yield\n"
			"", argv0);
	exit(EX_USAGE);
}

static void parse_options(int argc, char* argv[])
{
	char x;
	int error = 0;

	while (error == 0 && (x = getopt(argc, argv, "hT:I:S:Y")) != -1) {
		switch (x) {
			case 'h':
				print_help(argv[0]);
				break;
			case 'T':
				n_threads = atoi(optarg);
				break;
			case 'I':
				n_thread_iters = atoll(optarg);
				break;
			case 'S':
				interval_ns = atoll(optarg);
				break;
			case 'Y':
				yield_cpu = true;
				break;
			default:
				error = 1;
				break;
		}
	}
	if (error) {
		print_help(argv[0]);
	}
}

int main(int argc, char* argv[]) 
{
	parse_options(argc, argv);

	pthread_t threads[n_threads];

	fprintf(stderr, "Running %d threads each running %ld iterations with %luns intervals,%s yielding CPU\n",
			n_threads, n_thread_iters, interval_ns, yield_cpu ? "" : " not");

	register_fatal_sig_handlers();
	sleep(1);

	for(int i =  0; i < n_threads; i++) {
		pthread_create(&threads[i], 0 , do_log, 0);
	}

	for(int i =  0; i < n_threads; i++) {
		pthread_join(threads[i], 0);
	}

	sleep(1);
	return 0;
}

