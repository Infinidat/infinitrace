TRACES_ROOT_DIR:=$(abspath $(dir $(lastword $(MAKEFILE_LIST)))..)
CCWRAP=$(TRACES_ROOT_DIR)/ccwrap.py 
LDWRAP=$(TRACES_ROOT_DIR)/ldwrap.py
CC=$(CCWRAP) gcc
CXX=$(CCWRAP) g++
CXXFLAGS=-I..
LD=$(LDWRAP) ld
LDFLAGS=-L$(TRACES_ROOT_DIR)
all: demo

demo: demo.o
	$(CCWRAP) g++ $(LDFLAGS) demo.o -L.. -ltraceuser_per_process ../libparser.a ../libtraceuser_per_module.a ../libtraceutil.a -lrt -o demo -ldl

clean:
	rm demo.o demo
