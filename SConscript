import os
Import('xn_env')
Import('TracesDisabled')

# Libraries
#-------------

with TracesDisabled(xn_env) as untraced_env:
    optflags=Split("""$CCFLAGS -Wall -O2""")
    lib = untraced_env.SConscript("trace_instrumentor/SConscript")

    srcs = untraced_env.AutoSplit('''trace_user.c trace_metadata_util_untraced.c  halt.c trace_clock_untraced.c''')
    lib = untraced_env.XnStaticLibrary(target = 'traces', source = srcs, CCFLAGS = optflags)
    untraced_env.Alias('xn', lib)

    srcs = untraced_env.AutoSplit('''opt_util_untraced.c trace_str_util_untraced.c file_naming_untraced.c untraced_trace_clock_untraced.o''')
    lib = untraced_env.XnStaticLibrary(target = 'trace_util', source = srcs, CCFLAGS = optflags)
    untraced_env.Alias('xn', lib)
    
    srcs = untraced_env.AutoSplit('''snappy/snappy.c''')
    lib = untraced_env.XnStaticLibrary(target = 'snappy', source = srcs, CCFLAGS = optflags, CPPDEFINES = {'NDEBUG': '1'})
    untraced_env.Alias('xn', lib)

    srcs = untraced_env.AutoSplit('''trace_user_stubs.c ''')
    lib = untraced_env.XnStaticLibrary(target = 'tracesstubs', source = srcs, CCFLAGS = optflags)
    untraced_env.Alias('xn', lib)
    
    run_swig = os.environ.get('XN_SWIG', 0)
    if run_swig:
    	srcs = untraced_env.AutoSplit('''trace_user_stubs.c trace_user_stubs.i''')
    	lib = untraced_env.XnSharedLibrary(target = 'tracesstubs_swig', source = srcs, CCFLAGS = Split('-Wold-style-cast -w'), CXXFLAGS = Split('-g -ggdb'))
    	untraced_env.Alias('xn', lib)

safer_optflags=[f for f in optflags if not f.startswith('-O')] + ['-O1']

srcs = xn_env.AutoSplit('''validator.c trace_metadata_util.c''')
xn_env.BuildStaticLibraries(target = 'trace_bin_fmts', source = srcs, CCFLAGS = safer_optflags + ['-std=gnu99'])

srcs = xn_env.AutoSplit('''timeformat.c parser.c filter.c parser_mmap.c hashmap.c renderer.cpp''')
xn_env.BuildStaticLibraries(target = 'reader', source = srcs, CCFLAGS = optflags)

srcs = xn_env.AutoSplit('''opt_util.c trace_str_util.c trace_clock.c file_naming.c''')
xn_env.BuildStaticLibraries(target = 'trace_util_traced', source = srcs, CCFLAGS = optflags)

xn_env.Append(LIBPATH = Dir('.'))

with TracesDisabled(xn_env) as untraced_env:
    optflags=Split("""$CCFLAGS -Wall -O2""")
    srcs = untraced_env.AutoSplit('''reader.c dummy.cpp''')
    libs = ["reader", "trace_bin_fmts", "rt", "trace_util"]
    prog = untraced_env.XnProgram(target = "reader", source = srcs, LIBS = libs, CCFLAGS = optflags, LINKFLAGS="-lz")
    untraced_env.Alias('xn', prog)

    
xn_env.SConscript("trace_dumper/SConscript")
xn_env.SConscript("tools/SConscript")
