# Copyright (C) 2026 by Pretty5GS Contributors

libli_sources = files('''
    ogs-li.h
    target.c
    pdu.c
    http.c
'''.split())

libli_inc = include_directories('.')

libli = library('ogsli',
    sources : libli_sources,
    version : libogslib_version,
    include_directories : [libli_inc, libinc],
    dependencies : [libcore_dep, libproto_dep],
    install : true)

libli_dep = declare_dependency(
    link_with : libli,
    include_directories : [libli_inc, libinc],
    dependencies : [libcore_dep, libproto_dep])
