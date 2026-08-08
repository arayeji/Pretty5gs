# Copyright (C) 2026 by Pretty5GS Contributors

# This file is part of Open5GS / Pretty5GS.

libpcap_dep = dependency('libpcap', required : true)
libmicrohttpd_dep = dependency('libmicrohttpd', version : '>=0.9.40')
threads_dep = dependency('threads')

hiredis_dep = dependency('hiredis', required : false)
libcurl_dep = dependency('libcurl', required : false)

ptrace_c_args = []
ptrace_deps = [
    libapp_dep,
    libs1ap_dep,
    libpcap_dep,
    libmicrohttpd_dep,
    threads_dep,
]

if hiredis_dep.found()
    ptrace_c_args += ['-DHAVE_HIREDIS']
    ptrace_deps += [hiredis_dep]
endif

if libcurl_dep.found()
    ptrace_c_args += ['-DHAVE_LIBCURL']
    ptrace_deps += [libcurl_dep]
endif

libptrace_sources = files('''
    ptrace.h
    context.h
    context.c
    event.h
    event.c
    ptrace-sm.h
    ptrace-sm.c
    capture.h
    capture.c
    capture-ring.h
    capture-ring.c
    decode.h
    decode.c
    decode-s1ap.c
    decode-nas.c
    decode-gtpc.c
    decode-gtpu.c
    decode-pfcp.c
    decode-diameter.c
    identity.h
    identity.c
    target.h
    target.c
    correlate.h
    correlate.c
    cache.h
    cache.c
    rules.h
    rules.c
    store.h
    store.c
    store-redis.c
    store-clickhouse.c
    trace.h
    trace.c
    api.h
    api.c
    init.c
'''.split())

libptrace = static_library('ptrace',
    sources : libptrace_sources,
    c_args : ptrace_c_args,
    include_directories : srcinc,
    override_options : ['c_std=gnu11'],
    dependencies : ptrace_deps,
    install : false)

libptrace_dep = declare_dependency(
    link_with : libptrace,
    compile_args : ptrace_c_args,
    dependencies : ptrace_deps)

ptrace_sources = files('''
    app.c
    ../main.c
'''.split())

executable('open5gs-ptraced',
    sources : ptrace_sources,
    c_args : ['-DDEFAULT_CONFIG_FILENAME="@0@/ptrace.yaml"'.format(open5gs_sysconfdir)] + ptrace_c_args,
    include_directories : srcinc,
    override_options : ['c_std=gnu11'],
    dependencies : libptrace_dep,
    install_rpath : libdir,
    install : true)
