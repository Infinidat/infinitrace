Import('xn_env')
Import('TracesDisabled')

# Libraries
#-------------

with TracesDisabled(xn_env) as untraced_env:
    optflags=Split("""$CCFLAGS -Wall -O1""")
    lib = untraced_env.SConscript("trace_instrumentor/SConscript")

    srcs = untraced_env.AutoSplit('''trace_user.c trace_metadata_util_untraced.c  halt.c trace_clock_untraced.c''')
    lib = untraced_env.XnStaticLibrary(target = 'traces', source = srcs, CCFLAGS = optflags)
    untraced_env.Alias('xn', lib)

    srcs = untraced_env.AutoSplit('''opt_util_untraced.c trace_str_util_untraced.c file_naming_untraced.c untraced_trace_clock_untraced.o''')
    lib = untraced_env.XnStaticLibrary(target = 'trace_util', source = srcs, CCFLAGS = optflags)
    untraced_env.Alias('xn', lib)

    srcs = untraced_env.AutoSplit('''trace_user_stubs.c ''')
    lib = untraced_env.XnStaticLibrary(target = 'tracesstubs', source = srcs, CCFLAGS = optflags)
    untraced_env.Alias('xn', lib)

    srcs = xn_env.AutoSplit('''timeformat.c hashmap.c trace_metadata_util.c trace_parser.c''')
    lib = untraced_env.SharedLibrary(target = 'traces', source = srcs, CCFLAGS = optflags)
    xn_env.Alias('xn', lib)

objs = [Object(target = S + '.o', source = S + '.c', CCFLAGS = optflags)  for S in 'trace_metadata_util', 'hashmap']
srcs = xn_env.AutoSplit('''trace_parser.c validator.c''') + objs
xn_env.BuildStaticLibraries(target = 'tracereader', source = srcs, CCFLAGS = optflags)

srcs = xn_env.AutoSplit('''timeformat.c parser.c filter.c parser_mmap.c renderer.cpp''') + objs
xn_env.BuildStaticLibraries(target = 'reader', source = srcs, CCFLAGS = optflags)

srcs = xn_env.AutoSplit('''opt_util.c trace_str_util.c trace_clock.c file_naming.c''')
xn_env.BuildStaticLibraries(target = 'trace_util_traced', source = srcs, CCFLAGS = optflags)

xn_env.Append(LIBPATH = Dir('.'))

with TracesDisabled(xn_env) as untraced_env:
    optflags=Split("""$CCFLAGS -Wall -O2""")
    srcs = untraced_env.AutoSplit('''reader.c dummy.cpp''')
    libs = ["reader", "rt", "trace_util"]
    prog = untraced_env.XnProgram(target = "reader", source = srcs, LIBS = libs, CCFLAGS = optflags, LINKFLAGS="-lz")
    untraced_env.Alias('xn', prog)

# srcs = xn_env.AutoSplit('''hashmap.c trace_metadata_util.c trace_parser.c''')
# xn_env.BuildStaticLibraries(target = 'tracereader', source = srcs, CCFLAGS = optflags)
# xn_env.Append(LIBPATH = Dir('.'))

    
xn_env.SConscript("trace_dumper/SConscript")
xn_env.SConscript("trace_reader/SConscript")
xn_env.SConscript("tools/SConscript")
