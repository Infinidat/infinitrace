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

/* Trace dumper common formats and constants */

#ifndef __TRACE_DEFS_H__
#define __TRACE_DEFS_H__

#ifdef __cplusplus
 extern "C" {
#endif

 /*
  * The traces library uses two related binary format:
  	  * Data structures that reside in the shared-memory areas that are written by traced processes and read by the dumper.
  	  * A binary file format that is written by the trace dumper and read by the various reader applications, including the dumper's built-in reader.


 	 The trace file format
 	 =====================

  * The trace file is made out of 64 byte records. Each record contains a 20-byte header, which is identical for all record types and a 44 byte record body,
  * which is specific to each record type. Its full definition is given in the struct trace_record.
  *
  * Each record belongs to one of 3 classes:
  	  * Administrative records: A file header, an end-of-file record and special records indicating conditions like record loss.
  	  * Those records have no corresponding data structures	in the shared memory area.
  	  * Metadata records, which contain a "packetized" representation of the the metadata made available by the traced process in the static shared
  	    memory area (for more information about it, see below in the shared-memory format). The content of the metadata are is broken into 44-byte fragments which are packaged in metadata records.
  	    Every file starts with the metadata regions of all the processes that were being traced when the file was opened. Metadata regions can also appear
  	    in the middle of the file if a new process was detected after the file had been opened. see below for more information about the structure of metadata
  	    regions.
  	  * Trace data regions, where each record represents an event encountered at runtime. Here the on-disk format is identical to the in-memory format.
  	  	  The trace records belong to two classes:
  	    * Function trace records, reflecting entry to and exit from functions.
  	    * Typed records, reflecting explicit calls to the trace pseudo-functions (DEBUG, INFO, WARN etc.) in the traced process.
	  	  A trace data region is made of multiple dumps, where each dump corresponds to a single invocation of the writev() system call (see man 2 writev)
	  	  to write records from all the buffers that contain trace data. The first record in each dump is a dump header defined in
	  	  struct trace_record_dump_header. It stores the offset of the first record in the shared-memory area as well as the offset in the
	  	  file of the previous dump header. The subsequent records are copied verbatim from the shared-memory areas of the traced processes.


  	  The shared-memory format
  	  ========================

	Every traced processes creates 2 shared-memory areas for communicating with the trace dumper.
	* A static metadata area which includes the following, one after the other:
	  * A header defined in struct trace_metadata_region
	  * An array of log_descriptor_count log descriptors (see below struct trace_log_descriptor), each of which describes a spot in the code
	    where logging takes place - either explicitly (i.e. a typed record) or implicitly (function traces, if enabled).
	  * An array of type_definition_count type definitions (see below struct trace_type_definition). Each type definition can represent an enumeration,
	    a record (i.e. struct) or a typedef. The possible values are defined in the enum trace_type_id.
	  * An array of trace descriptor parameters (see below struct trace_param_descriptor) referenced by the log descriptors. The final element of
	    this array has its name set to NULL.
	  * An array of enum name and numeric value pairs (see below struct trace_enum_value). The final element of this array has its name set to NULL.
	  * A string table, containing a sequence of all the constant strings used by the other structures for to designate constant strings in
	    the user code, parameter names, enum value names etc.

	  Many of these structures refer to each others by pointers. Whenever this data structure is created or relocated, its base address is stored in
	  the base_address field of the header. Whenever the entire data structure is copied to a different base address, all the pointers need to be adjusted
	  by the difference between the old address stored in the header and the new address where it has been placed.

	* A dynamic trace data area which contains data that is modified as traces are written.
	  Note: The structures for this shared-memory area are defined and documented in detail in trace_lib.h
	  The overall structure of the dynamic data area is defined by the structure trace_buffer. It contains a header giving the process' pid
	  and 3 trace buffers for each of the 3 trace classes: function traces, debug and everything else.
  */



#define MAX_METADATA_SIZE (0x1000000) /* An upper bound on the possible size of metadata */
#define TRACE_BUFFER_NUM_RECORDS (3)  /* The number of trace buffers per traced process */

 /* TODO: Add compile-time checking that the number is a power of 2. Nothing else will likely work */
#define TRACE_RECORD_BUFFER_RECS  0x100000

     
#define TRACE_SEVERITY_DEF       \
     TRACE_SEV_X(0, INVALID)     \
     TRACE_SEV_X(1, FUNC_TRACE)  \
     TRACE_SEV_X(2, DEBUG)       \
     TRACE_SEV_X(3, INFO)        \
     TRACE_SEV_X(4, WARN)        \
     TRACE_SEV_X(5, ERR)       \
     TRACE_SEV_X(6, FATAL)       \

enum trace_severity {
#define TRACE_SEV_X(num, name) \
	TRACE_SEV_##name  = num,

TRACE_SEVERITY_DEF
        TRACE_SEV__MIN = 1,
        TRACE_SEV__MAX = TRACE_SEV_FATAL
#undef TRACE_SEV_X
};

/* The trace record type constants defined below are used in the rec_type field of the trace_record structure */

enum trace_rec_type {
	TRACE_REC_TYPE_UNKNOWN = 0,
	TRACE_REC_TYPE_TYPED = 1,		/* A produced by the user logging explicitly or function traces */
	TRACE_REC_TYPE_FILE_HEADER = 2,	/* Appears only at the start of a new file */
	
	/* For every process that is being traced the file contains a metadata block,
	   comprising a metadata header and metadata payload records. */
	TRACE_REC_TYPE_METADATA_HEADER = 3,
	TRACE_REC_TYPE_METADATA_PAYLOAD = 4,
	
	/* Appears at the beginning of every sequence of data written in a single writev() invocation */
	TRACE_REC_TYPE_DUMP_HEADER = 5,

	/* Appears before the data records for every sequence of records written for an individual mapped buffer within a given dump */
	TRACE_REC_TYPE_BUFFER_CHUNK = 6,

    TRACE_REC_TYPE_END_OF_FILE = 7,

    /* Inserted to indicate data loss */
    TRACE_REC_TYPE_DATA_LOSS = 8,
};

enum trace_log_descriptor_kind {
	/* For function traces */
    TRACE_LOG_DESCRIPTOR_KIND_FUNC_ENTRY = 0,
    TRACE_LOG_DESCRIPTOR_KIND_FUNC_LEAVE = 1,

    /* Explicit logging, (a.k.a typed records) */
    TRACE_LOG_DESCRIPTOR_KIND_EXPLICIT = 2,
};

#define TRACE_RECORD_SIZE           64
#define TRACE_RECORD_PAYLOAD_SIZE   44
#define TRACE_RECORD_HEADER_SIZE    (TRACE_RECORD_SIZE - TRACE_RECORD_PAYLOAD_SIZE)

  /* Indicate whether the current record is the first or last of a sequence. It's possible (and common) for both flags to be set */
enum trace_termination_type {
	TRACE_TERMINATION_LAST = 1,
	TRACE_TERMINATION_FIRST = 2
};

#define TRACE_MACHINE_ID_SIZE    0x18

/* Currently unused */
enum trace_file_type {
	TRACE_FILE_TYPE_JOURNAL = 1,
	TRACE_FILE_TYPE_SNAPSHOT = 2
};

 struct trace_enum_value;
     
 enum trace_type_id {
    TRACE_TYPE_ID_ENUM = 1,
    TRACE_TYPE_ID_RECORD = 2,
    TRACE_TYPE_ID_TYPEDEF = 3
};

#ifndef TRACE_FORMAT_VERSION
#define TRACE_FORMAT_VERSION (0xA2)
#endif

#define TRACE_FORMAT_VERSION_INTRODUCED_FILE_FUNCTION_METADATA (0xA2)
#define TRACE_FORMAT_VERSION_INTRODUCED_DEAD_PID_LIST (0xA2)

 /* Information about user defined types */
struct trace_type_definition {
    enum trace_type_id type_id;
    const char *type_name;
    union  {
        // void * is used to allow static initialization of the union in C++, which does not support designated initializers
        void *params;

        /* An array of pointers to trace_enum_value structures (defined below). The last member of the array has its name field set to NULL */
        struct trace_enum_value *enum_values;
    };
};

 struct trace_enum_value {
    const char *name;
    unsigned int value;
};

 /* We are making a dubious assumption here the process and thread ids are 16-bit long.
  * This is true in practice in current common POSIX systems but is deprecated. */
typedef unsigned short int trace_pid_t;

/* Time-stamps and time intervals in nano-seconds */
typedef unsigned long long trace_ts_t;

struct trace_record {
	/* 20 bytes header */
	trace_ts_t  ts;
	trace_pid_t pid;		/* Process ID */
	trace_pid_t tid;		/* Thread ID */
    short nesting;			/* Call stack depth for the current thread, used for function traces. */
	unsigned termination:2; /* The values of trace_termination_type, possible or-ed */
	unsigned reserved:6;
	unsigned severity:4;	/* One of the values of the trace_severity enum */
	unsigned rec_type:4;	/* One of the values of the trace_rec_type enum */

	/* A counter that is incremented every-time the writing of records from the traced process wraps around to the beginning
	 * of the buffer */
	unsigned int generation;

	/* 44 bytes payload */
	union trace_record_u {
		/* Used for records without a predefined payload structure, of types TRACE_REC_TYPE_METADATA_PAYLOAD and TRACE_REC_TYPE_END_OF_FILE */
		unsigned char payload[TRACE_RECORD_PAYLOAD_SIZE];
		
		/* Payload for TRACE_REC_TYPE_TYPED */
		struct trace_record_typed {
			unsigned int log_id;	/* Index to the array of log descriptors in the metadata */
			unsigned char payload[];
		} typed;

		/* Payload for TRACE_REC_TYPE_FILE_HEADER */
		struct trace_record_file_header {
			unsigned char machine_id[TRACE_MACHINE_ID_SIZE];	/* machine hostname, truncated to TRACE_MACHINE_ID_SIZE - 1 characters */
            unsigned short format_version;						/* Revision of the file format */
            unsigned char  reserved[6];
            unsigned int magic;		/* Should contain TRACE_MAGIC_FILE_HEADER */
		} file_header;

		/* Payload for TRACE_REC_TYPE_METADATA_HEADER */
		struct trace_record_metadata {
			unsigned int metadata_size_bytes;
			trace_pid_t  dead_pids[4];  /* PIDs of processes that have ended and whose resources in the parser should be reclaimed. */

			/* Protect against early versions of the dumper that did not zero-out the metadata header before writing. */
			unsigned char reserved[TRACE_RECORD_PAYLOAD_SIZE - 4*sizeof(trace_pid_t) - 2*sizeof(unsigned)];
			unsigned int metadata_magic;  /* Should contain TRACE_MAGIC_METADATA */
		} metadata;

		/* Payload for TRACE_REC_TYPE_DUMP_HEADER */
		struct trace_record_dump_header {
			/* Offset in the file of the previous dump, allowing the file to be searched backwards. */
			unsigned int prev_dump_offset;

			/* Total number of trace records in the dump */
			unsigned int total_dump_size;

			/* Offset of the first chunk header in the dump */
            unsigned int first_chunk_offset;
		} dump_header;

		/* Payload for TRACE_REC_TYPE_BUFFER_CHUNK */
		struct trace_record_buffer_dump {
			/* Last offset containing metadata for the current traced process */
			unsigned int last_metadata_offset;

			/* Previous chunk for the current traced process. */
			unsigned int prev_chunk_offset;

			/* Offset of the dump to which this chunk belongs */
			unsigned int dump_header_offset;

			/* Traced process time-stamp at which the chunk starts */
			trace_ts_t ts;

			/* Number of records in the chunk */
			unsigned int records;

			/* A bit mask representing the severity levels that may be found in this chunk */
			unsigned int severity_type;
            unsigned int lost_records;
		} buffer_chunk;

		/* Payload for TRACE_REC_TYPE_DATA_LOSS */
		/* Note: not implemented yet, will be revised and possibly merged with the chunk header */
		struct trace_record_data_loss {
			unsigned int lost_records;
			unsigned long long ts_start;
			unsigned long long ts_end;
		} data_loss;
	} __attribute__((packed)) u;
} __attribute__((packed));

/* Flags used to indicate the type of trace parameters */
enum trace_param_desc_flags {
	/* Numerical types of 8 - 64 bits */
	TRACE_PARAM_FLAG_NUM_8    = 0x001,
	TRACE_PARAM_FLAG_NUM_16   = 0x002,
	TRACE_PARAM_FLAG_NUM_32   = 0x004,
	TRACE_PARAM_FLAG_NUM_64   = 0x008,

	/* An array rather than a scalar. Arrays have size information stored in their first byte as follows:
	 * Bits 0 - 6 give the length of the array.
	 * Bit  7 is a flag indicating whether the array is continued in the next value (1) or not (0)
	 * Subsequent bytes contain the array members */
	TRACE_PARAM_FLAG_VARRAY   = 0x010,

	/* Strings that are known at compile time, and hence are stored in the metadata string table. The string
	 * is pointed to by the const_str field */
	TRACE_PARAM_FLAG_CSTR     = 0x020,

	/* C-style strings that are only known at runtime, and hence stored as part of the data.
	 * The length of the string is given in the same way as for VARRAY above */
	TRACE_PARAM_FLAG_STR      = 0x040,

	TRACE_PARAM_FLAG_BLOB     = 0x080,	/* Currently unused */

	TRACE_PARAM_FLAG_UNSIGNED = 0x100,	/* Interpret the value as unsigned */
	TRACE_PARAM_FLAG_HEX      = 0x200,	/* Display the value as hex */
	TRACE_PARAM_FLAG_ZERO     = 0x400,	/* Display with a leading zero */

	/* Specify an enumeration whose name is given in the type_name field. Instead of displaying the numeric value look-up the
	 * corresponding vale name */
    TRACE_PARAM_FLAG_ENUM     = 0x800,

    /* The fields of a composite object follow. This can be either a struct containing plain-old-data,
     * or an object that implements the __repr__ method. */
    TRACE_PARAM_FLAG_NESTED_LOG   = 0x1000,

    /* Flags for function traces */
    TRACE_PARAM_FLAG_ENTER    = 0x2000,
    TRACE_PARAM_FLAG_LEAVE    = 0x4000,

    TRACE_PARAM_FLAG_TYPEDEF  = 0x8000,	/* Currently unused */

    /* Parameters that have specific names, e.g. function arguments */
    TRACE_PARAM_FLAG_NAMED_PARAM  = 0x10000,

    /* structures with plain-old-data */
    TRACE_PARAM_FLAG_RECORD  = 0x20000,

#if (TRACE_FORMAT_VERSION >= 0xA2)
    /* The parameter is known at compile-time.
     * A future version of the parser will display the value in describe_params mode (e.g. when displaying statistics)
     * instead of the type name */
    TRACE_PARAM_FLAG_CONST   = 0x40000,
#endif
};

enum trace_magic_numbers {
	TRACE_MAGIC_FILE_HEADER  = 0xACEF42FA,
	TRACE_MAGIC_METADATA	 = 0xDEADBAAF
};

/* Descriptor for an individual parameter being logged */
struct trace_param_descriptor {
	unsigned long flags;
    const char *param_name;	/* Used for named parameters, e.gf function arguments */
    union {		/* The field that is used is determined by the flags, see their descriptions above */
        const char *str;
        const char *const_str;	/* Pointer to a string in the matadata string table. */
        const char *type_name;	/* for records, enums etc. */
    };
};

/* Descriptor for an individual instance of logging in the code, e.g. an invocation of DEBUG(), etc.
 * NOTE: The size of this data structure should be kept no greater than 32 bytes. Otherwise the linker script created by ldwrap.py will have to be changed */
struct trace_log_descriptor {
    enum trace_log_descriptor_kind kind;	/* Function entry/exit or typed record */
#if (TRACE_FORMAT_VERSION >= TRACE_FORMAT_VERSION_INTRODUCED_FILE_FUNCTION_METADATA)
    unsigned line : 20;		/* Line in the code where the trace appears */
    unsigned severity : 4;	/* A value from the trace_severity enum */
#endif
    const struct trace_param_descriptor *params;
#if (TRACE_FORMAT_VERSION >= TRACE_FORMAT_VERSION_INTRODUCED_FILE_FUNCTION_METADATA)
    const char *file;		/* File in the code where the trace appears */
    const char *function;	/* Function where the trace appears */
#endif
};


/* Metadata region header. For a full description of its layout see above at the top of the file. */

struct trace_metadata_region {
    char name[0x100];			/* The name of the process */
    void *base_address;			/* Base address which was used at the time the various pointer fields in the data-structure were filled. */
    unsigned long log_descriptor_count;
    unsigned long type_definition_count;
    char data[];  /* Place-holder for the actual metadata, when it is placed right after the header fields above (e.g. in the trace parser) */
};
     
     
/* Used to control at runtime what data will be written to the trace */
struct trace_runtime_control {
	enum trace_severity default_min_sev; /* Minimum severity for reporting. Per-subsystem definitions take precedence over it */
	/* TODO: Define per-subsystem severity limits. */
};
     
#ifdef __cplusplus
}
#endif

#endif 
