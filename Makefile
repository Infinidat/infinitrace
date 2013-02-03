CFLAGS=-I. -c -Wall -g -std=gnu99 -fPIC
LIBTRACE_OBJS=trace_metadata_util.o trace_parser.o halt.o hashmap.o validator.o
LIBPARSER_OBJS=timeformat.o parser.o filter.o parser_mmap.o hashmap.o trace_metadata_util.o
LIBTRACEUSER_OBJS=trace_metadata_util.o trace_user.o halt.o trace_clock.o
LIBTRACEUTIL_OBJS=opt_util.o trace_str_util.o file_naming.o
DUMPER_OBJS=trace_dumper/trace_dumper.o trace_dumper/filesystem.o trace_dumper/writer.o trace_dumper/write_prep.o trace_dumper/buffers.o trace_dumper/init.o trace_dumper/open_close.o trace_dumper/metadata.o trace_dumper/housekeeping.o trace_user_stubs.o

TARGET_PLATFORM=$(shell gcc -v 2>&1|fgrep Target|cut -d':' -d' ' -f2|cut -d'-' -f 2,3)
EXTRA_LIBS=
ALL_TARGETS=libtrace simple_trace_reader dump_file_diags reader 
# Note that interactive_reader has been removed from the default build
 
ifeq ($(TARGET_PLATFORM),linux-gnu)
       EXTRA_LIBS+=-lrt
       LIBTRACEUTIL_OBJS+=trace_clock.o
       ALL_TARGETS+=libtraceuser trace_dumper trace_instrumentor
endif

ifndef DISABLE_OPT  # Make sure to set this variable when building on Mac inside Eclipse, otherwise debugging will fail
       CFLAGS+=-O2
endif

all: $(ALL_TARGETS)
trace_dumper: libtrace libtraceutil $(DUMPER_OBJS)
	gcc -L.  $(DUMPER_OBJS) -ltrace -ltraceutil $(EXTRA_LIBS) -o trace_dumper/trace_dumper 

libtrace: $(LIBTRACE_OBJS) libtraceutil
	ar rcs libtrace.a $(LIBTRACE_OBJS)
	gcc -shared -g $(LIBTRACE_OBJS) -L. -ltraceutil -o traces.so

libtraceuser: $(LIBTRACEUSER_OBJS)
	ar rcs libtraceuser.a $(LIBTRACEUSER_OBJS)
	
libtraceutil: $(LIBTRACEUTIL_OBJS)
	ar rcs libtraceutil.a  $(LIBTRACEUTIL_OBJS)

libparser: $(LIBPARSER_OBJS)
	ar rsc libparser.a $(LIBPARSER_OBJS) 

simple_trace_reader: libtrace libtraceutil trace_reader/simple_trace_reader.o
	gcc -L. trace_reader/simple_trace_reader.o -ltrace -ltraceutil $(EXTRA_LIBS) -o trace_reader/simple_trace_reader

reader: libparser libtraceutil reader.o
	gcc -L. reader.o -lparser -ltraceutil -lz $(EXTRA_LIBS) -o reader

interactive_reader: trace_parser.h
	h2xml  -c -I. trace_parser.h -o _trace_parser_ctypes.xml
	xml2py -k f -k e -k s _trace_parser_ctypes.xml > interactive_reader/_trace_parser_ctypes.py
	rm _trace_parser_ctypes.xml

dump_file_diags: libtraceutil tools/dump_file_diags.o trace_defs.h
	gcc -L. tools/dump_file_diags.o -ltraceutil -o tools/dump_file_diags

trace_instrumentor/trace_instrumentor.o: CXXFLAGS := $(shell llvm-config --cxxflags) -g
trace_instrumentor/trace_instrumentor.o: LDFLAGS := $(shell llvm-config --libs --ldflags)
trace_instrumentor: trace_instrumentor/trace_instrumentor.o
	gcc $(LDFLAGS) -shared trace_instrumentor/trace_instrumentor.o  -o trace_instrumentor/trace_instrumentor.so

clean:
	rm -f *.o trace_reader/simple_trace_reader.o reader trace_reader/simple_trace_reader trace_dumper/*.o trace_instrumentor/*.o tools/*.o trace_instrumentor/*.so trace_dumper/trace_dumper trace_reader/trace_reader *so *.a
