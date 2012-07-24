Import('xn_env')
Import('TracesDisabled')

# Libraries
#-------------

with TracesDisabled(xn_env) as untraced_env:
    lib = untraced_env.SConscript("trace_instrumentor/SConscript")

    srcs = untraced_env.AutoSplit('''trace_user.c trace_metadata_util_untraced.c  halt.c''')
    lib = untraced_env.XnStaticLibrary(target = 'traces', source = srcs)
    untraced_env.Alias('xn', lib)

    srcs = untraced_env.AutoSplit('''trace_user_stubs.c trace_metadata_util_untraced.c ''')
    lib = untraced_env.XnStaticLibrary(target = 'tracesstubs', source = srcs)
    untraced_env.Alias('xn', lib)

    srcs = xn_env.AutoSplit('''trace_metadata_util.c cached_file.c trace_parser.c''')
    lib = untraced_env.SharedLibrary(target = 'traces', source = srcs)    
    xn_env.Alias('xn', lib)


srcs = xn_env.AutoSplit('''trace_metadata_util.c cached_file.c trace_parser.c''')
xn_env.BuildStaticLibraries(target = 'tracereader', source = srcs)
xn_env.Append(LIBPATH = Dir('.'))

    
xn_env.SConscript("trace_dumper/SConscript")
xn_env.SConscript("trace_reader/SConscript")
xn_env.SConscript("tools/SConscript")
