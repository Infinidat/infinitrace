CPPFLAGS=-I. -c -Wall -g -fPIC
CFLAGS=-std=gnu99
CXXFLAGS=-fno-rtti
LIBTRACE_OBJS=trace_metadata_util.o halt.o 
LIBPARSER_OBJS=timeformat.o parser.o parser_stats.o renderer.o filter.o parser_mmap.o hashmap.o trace_shm_util.o trace_metadata_util.o hashmap.o validator.o
LIBTRACEUSER_PER_PROCESS_OBJS=trace_user_per_process.o trace_user_shm_setup.o halt.o trace_clock.o
LIBTRACEUSER_PER_MODULE_OBJS=trace_user_per_module.o
LIBTRACEUTIL_OBJS=opt_util.o trace_str_util.o file_naming.o trace_clock.o trace_mmap_util.o
LIBSNAPPY_OBJS=snappy/snappy.o
DUMPER_OBJS=trace_dumper/trace_dumper.o trace_dumper/filesystem.o trace_dumper/events.o trace_dumper/sgio_util.o trace_dumper/internal_buffer.o trace_dumper/mm_writer.o trace_dumper/writer.o trace_dumper/write_prep.o trace_dumper/buffers.o trace_dumper/init.o trace_dumper/open_close.o trace_dumper/metadata.o trace_dumper/housekeeping.o trace_user_stubs.o

TARGET_PLATFORM=$(shell gcc -v 2>&1|fgrep Target|cut -d':' -d' ' -f2|cut -d'-' -f 2,3)
CLANG=clang
REQUIRED_CLANG_VER=3.3
CLANG_VER=$(shell which $(CLANG) > /dev/null && $(CLANG) --version|head -1|grep -oP '\d\.\d '|cut -d' ' -f1)

EXTRA_LIBS=
ALL_TARGETS=libtrace dump_file_diags reader 
# Note that interactive_reader has been removed from the default build
 
ifeq ($(TARGET_PLATFORM),linux-gnu)
       EXTRA_LIBS+=-lrt -lpthread
       ALL_TARGETS+=libtraceuser_per_process libtraceuser_per_module trace_dumper trace_instrumentor libtrace_so
       LIBTRACEUTIL_OBJS+=trace_proc_util.o
endif

ifndef DISABLE_OPT  # Make sure to set this variable when building on Mac inside Eclipse, otherwise debugging will fail
       CFLAGS+=-O2
endif

all: $(ALL_TARGETS)

trace_dumper: libtrace libtraceutil libsnappy libparser $(DUMPER_OBJS)
	gcc -L.  $(DUMPER_OBJS) -ltrace -ltraceutil -lparser -lsnappy $(EXTRA_LIBS) -o trace_dumper/trace_dumper 

libtrace: $(LIBTRACE_OBJS) libtraceutil
	ar rcs libtrace.a $(LIBTRACE_OBJS)
	
libtrace_so: libtrace
	gcc -shared -g $(LIBTRACE_OBJS) -L. -ltraceutil -o traces.so

libtraceuser_per_process: $(LIBTRACEUSER_PER_PROCESS_OBJS)
	gcc -shared -g $(LIBTRACEUSER_PER_PROCESS_OBJS) -L. -o libtraceuser_per_process.so

libtraceuser_per_module: $(LIBTRACEUSER_PER_MODULE_OBJS)
	ar rcs libtraceuser_per_module.a $(LIBTRACEUSER_PER_MODULE_OBJS)
	
libtraceutil: $(LIBTRACEUTIL_OBJS)
	ar rcs libtraceutil.a  $(LIBTRACEUTIL_OBJS)

libsnappy: $(LIBSNAPPY_OBJS)
	ar rcs libsnappy.a  $(LIBSNAPPY_OBJS)

libparser: $(LIBPARSER_OBJS)
	ar rsc libparser.a $(LIBPARSER_OBJS) 

reader: libparser libtraceutil libsnappy reader.o
	g++ -L. reader.o -lparser -ltraceutil -lsnappy -lz $(EXTRA_LIBS) -o reader

dump_file_diags: libtraceutil tools/dump_file_diags.o trace_defs.h
	gcc -L. tools/dump_file_diags.o -ltraceutil -o tools/dump_file_diags

ifeq ($(CLANG_VER),$(REQUIRED_CLANG_VER))

TRACE_INSTROMENTOR_OBJS=trace_instrumentor/trace_instrumentor.o trace_instrumentor/trace_call.o trace_instrumentor/trace_param.o trace_instrumentor/util.o

$(TRACE_INSTROMENTOR_OBJS): CXXFLAGS := $(shell llvm-config --cxxflags) -g
$(TRACE_INSTROMENTOR_OBJS): LDFLAGS := $(shell llvm-config --libs --ldflags)

trace_instrumentor: $(TRACE_INSTROMENTOR_OBJS)
	g++ $(LDFLAGS) -shared $(TRACE_INSTROMENTOR_OBJS) -o trace_instrumentor/trace_instrumentor.so
	
else
ifeq ($(CLANG_VER),)

.PHONY: trace_instrumentor
trace_instrumentor: ; $(warning No clang found, skipping instrumentor build)

else

.PHONY: trace_instrumentor
trace_instrumentor: ; $(warning Wrong clang version $(CLANG_VER) found. Version $(REQUIRED_CLANG_VER) is required, skipping instrumentor build)

endif
endif

clean:
	rm -f *.o trace_reader/simple_trace_reader.o reader trace_reader/simple_trace_reader trace_dumper/*.o trace_instrumentor/*.o tools/*.o snappy/*.o trace_instrumentor/*.so trace_dumper/trace_dumper trace_reader/trace_reader *so *.a
