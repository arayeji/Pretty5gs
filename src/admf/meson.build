# Copyright (C) 2026 by Pretty5GS Contributors

libmicrohttpd_dep = dependency('libmicrohttpd', version: '>=0.9.40')

libadmf_sources = files('''
    context.h
    context.c
    hi1.h
    hi1.c
    x1.h
    x1.c
    mdf2.h
    mdf2.c
    init.c
'''.split())

libadmf = static_library('admf',
    sources : libadmf_sources,
    include_directories : srcinc,
    dependencies : [libapp_dep, libli_dep, libmicrohttpd_dep],
    install : false)

libadmf_dep = declare_dependency(
    link_with : libadmf,
    dependencies : [libapp_dep, libli_dep, libmicrohttpd_dep])

admf_sources = files('''
    app.c
    ../main.c
'''.split())

executable('open5gs-admfd',
    sources : admf_sources,
    c_args : '-DDEFAULT_CONFIG_FILENAME="@0@/admf.yaml"'.format(open5gs_sysconfdir),
    include_directories : srcinc,
    dependencies : libadmf_dep,
    install_rpath : libdir,
    install : true)
