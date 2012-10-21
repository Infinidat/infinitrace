#include "../platform.h"

#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <sysexits.h>
#include <errno.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <limits.h>

#include "../bool.h"
#include "../trace_defs.h"
#include "../opt_util.h"
#include "../array_length.h"

enum {
	MAX_THREADS = 1 << (8 * sizeof(trace_pid_t))
};

unsigned long record_num = 0;
unsigned long record_range[] = { 0, ULONG_MAX };

struct thread_access_info_t {
	trace_ts_t last_ts;
	unsigned   last_n;
};

bool_t show_duplicates = FALSE;
bool_t show_out_of_order = FALSE;

const char **filenames = NULL;

static int parse_options(int argc, const char *argv[])
{
	static const struct option long_opts[] = {
	    { "help", 0, 0, 'h'},
		{ "duplicate", 0, 0, 'd'},
		{ "out-of-order", 0, 0, 'o'},
		{ "begin", required_argument, 0, 'b'},
		{ "end", required_argument, 0, 'e'},
		{ 0, 0, 0, 0}
	};

    int o;
    int longindex;

	char short_opts[MAX_SHORT_OPTS_LEN(ARRAY_LENGTH(long_opts))];
	short_opts_from_long_opts(short_opts, long_opts);

	static const char help_text[] =
			"%s [options] [files]\n"
			"Available options:\n"
			"-h    print this text\n"
			"-d    show duplicate records (A timestamp recurring in the same thread)\n"
			"-o    show out-of-order records (when a record has an earlier timestamp than one appearing earlier in the file\n"
			"-b n  begin at record n\n"
			"-e n  end at record n\n";

	while ((o = getopt_long(argc, (char *const *)argv, short_opts, long_opts, &longindex)) != EOF) {
		switch (o) {
		case 'h':
			printf(help_text, argv[0]);
			return 1;

		case 'd':
			show_duplicates = TRUE;
			break;

		case 'o':
			show_out_of_order = TRUE;
			break;

		case 'b':
			record_range[0] = strtoul(optarg, NULL, 10);
			break;

		case 'e':
			record_range[1] = strtoul(optarg, NULL, 10);
			break;

		default:
			fprintf(stderr, "Unrecognized option %c\n", o);
			return EX_USAGE;
		}
	}

	filenames = argv + optind;
	if (NULL == *filenames) {
		fprintf(stderr, "%s: No filenames specified. Usage:\n", argv[0]);
		fprintf(stderr, help_text, argv[0]);
		return EX_USAGE;
	}

	return 0;
}


static struct thread_access_info_t thread_access_info[MAX_THREADS] = { { 0, 0 } };

static void validate_timestamp(const struct trace_record *rec)
{
	assert(TRACE_REC_TYPE_TYPED == rec->rec_type);
	trace_pid_t tid = rec->tid;

	if (0 == (rec->termination & TRACE_TERMINATION_FIRST)) {
		return;
	}

	if (rec->ts <= thread_access_info[tid].last_ts) {
		if (rec->ts == thread_access_info[tid].last_ts) {
			if (show_duplicates)
				printf("n=%lu: \t\tDuplicate record with sev=%u for thread %u last accessed n=%u, with ts=%llu \n", record_num, rec->severity, tid, thread_access_info[tid].last_n, rec->ts);
		}
		else if (show_out_of_order) {
			printf("n=%lu: \t\tOut of order record with sev=%u for thread %u last accessed n=%u, with ts=%llu < %llu\n", record_num, rec->severity, tid, thread_access_info[tid].last_n, rec->ts, thread_access_info[tid].last_ts);
		}
	}
	else {
		thread_access_info[tid].last_ts = rec->ts;
		thread_access_info[tid].last_n  = record_num;
	}
}

static int print_end_diagnostics(int last_read_bytes_num)
{

	if (last_read_bytes_num < 0) {
		fprintf(stderr, "Error reading file: %s\n", strerror(errno));
		return EX_IOERR;
	}

	if ((last_read_bytes_num > 0) && (last_read_bytes_num != TRACE_RECORD_SIZE)) {
		fprintf(stderr, "The file ends with an incomplete record with %d bytes\n", last_read_bytes_num);
		return EX_DATAERR;
	}

	return 0;
}

static int process_records(int fd)
{

	unsigned metadata_len = 0;
	unsigned data_records = 0;
	int rc = 0;
	struct trace_record rec;

	for (record_num = record_range[0]; record_num <= record_range[1] ; record_num++) {
		rc = read(fd, &rec, TRACE_RECORD_SIZE);
		if (TRACE_RECORD_SIZE != rc) {
			break;
		}

		if (! (TRACE_TERMINATION_FIRST & rec.termination)) {
			continue;
		}

		if (TRACE_REC_TYPE_TYPED == rec.rec_type) {
			validate_timestamp(&rec);
			data_records++;
			continue;
		}

		if (data_records > 0) {
			printf("n=%lu: \t\tChunk ended with %u records\n", record_num, data_records);
		}
		data_records = 0;

		switch(rec.rec_type) {
		case TRACE_REC_TYPE_METADATA_PAYLOAD:
			if (rec.termination & TRACE_TERMINATION_LAST) {
				printf("n=%lu: \tEnd of metadata block of %u records for pid=%u\n", record_num, metadata_len, rec.pid);
			}
			else metadata_len++;
			break;

		case TRACE_REC_TYPE_METADATA_HEADER:
			printf("n=%lu: \tStart of %u byte metadata block for pid=%u\n", record_num, rec.u.metadata.metadata_size_bytes, rec.pid);
			metadata_len = 0;
			break;

		case TRACE_REC_TYPE_DUMP_HEADER:
			printf("n=%lu: \tDump size=%u, first chunk at %u\n", record_num, rec.u.dump_header.total_dump_size, rec.u.dump_header.first_chunk_offset);
			break;

		case TRACE_REC_TYPE_BUFFER_CHUNK:
			printf("n=%lu: \t\tChunk recs=%u, ts=%llu, sev_mask=%X, lost=%u\n",
					record_num,
					rec.u.buffer_chunk.records,
					rec.u.buffer_chunk.ts,
					rec.u.buffer_chunk.severity_type,
					rec.u.buffer_chunk.lost_records);
			break;

		case TRACE_REC_TYPE_FILE_HEADER:
			printf("n=%lu: Start of file. Format ver=%X, flags = %X\n", record_num, rec.u.file_header.format_version, rec.u.file_header.flags);
			break;

		case TRACE_REC_TYPE_END_OF_FILE:
			printf("n=%lu: End of file\n", record_num);
			break;

		default:
			printf("n=%lu: Unrecognized record of type %d\n", record_num, rec.rec_type);
			break;
		}
	}

	return print_end_diagnostics(rc);
}

int main(int argc, const char *argv[])
{
	int rc = parse_options(argc, argv);
	switch (rc) {
	case 1:  /* User asked usage to be printed */
		return 0;

	case 0:
		break;

	default:
		return rc;
	}

	do {
		int fd = open(*filenames, O_RDONLY);
		if (fd < 0) {
			rc = EX_NOINPUT;
		}
		else {
			rc = lseek64(fd, record_range[0] * TRACE_RECORD_SIZE, SEEK_SET);
			if (rc < 0) {
				fprintf(stderr, "Could not seek to record %lu in %s due to %s", record_range[0], *filenames, strerror(errno));
				rc = EX_DATAERR;
			}
			else {
				rc = process_records(fd);
			}
		}
	} while((0 == rc) && (*(filenames++) != NULL));

	return rc;
}
