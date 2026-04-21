# Copyright (C) 2026 by Open5GS Contributors

# This file is part of Open5GS.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

libcgf_sources = files('''
    context.h
    context.c

    event.h
    event.c

    gtpp-path.h
    gtpp-path.c

    spool.h
    spool.c

    cgf-sm.h
    cgf-sm.c

    init.c
'''.split())

libcgf_deps = [libapp_dep]
libcgf_c_args = []

if admin_watcher_enabled
    libcgf_sources += files('cgf-admin-watcher.h', 'cgf-admin-watcher.c')
    libcgf_deps += [open5gs_admin_watcher_dep]
    libcgf_c_args += ['-DOPEN5GS_ADMIN_WATCHER']
endif

libcgf = static_library('cgf',
    sources : libcgf_sources,
    c_args : libcgf_c_args,
    dependencies : libcgf_deps,
    install : false)

libcgf_dep = declare_dependency(
    link_with : libcgf,
    compile_args : libcgf_c_args,
    dependencies : libcgf_deps)

cgf_sources = files('''
    app.c
    ../main.c
'''.split())

executable('open5gs-cgfd',
    sources : cgf_sources,
    c_args : '-DDEFAULT_CONFIG_FILENAME="@0@/cgf.yaml"'.format(open5gs_sysconfdir),
    include_directories : srcinc,
    dependencies : libcgf_dep,
    install_rpath : libdir,
    install : true)
