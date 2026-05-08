# Copyright (C) 2019 by Sukchan Lee <acetcom@gmail.com>

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

_mopts = join_paths(meson.source_root(), 'meson_options.txt')
grep_prog = find_program('grep', native: true, required: false)
_mysql_pcrf_declared = false
if grep_prog.found()
  _gr = run_command(grep_prog, '-qF', 'option(\'mysql_pcrf\'', _mopts, check: false)
  _mysql_pcrf_declared = (_gr.returncode() == 0)
endif

mysql_pcrf_opt = false
if _mysql_pcrf_declared
  mysql_pcrf_opt = get_option('mysql_pcrf')
endif

mysql_dep = declare_dependency()
mysql_cargs = []
if mysql_pcrf_opt
    mysql_dep = dependency('mysqlclient', required: false)
    if not mysql_dep.found()
        mysql_dep = dependency('libmariadb', required: false)
    endif
    if not mysql_dep.found()
        mysql_dep = dependency('mariadb', required: false)
    endif
    if not mysql_dep.found()
        mysql_lib = cc.find_library('mysqlclient', required: false)
        if mysql_lib.found()
            # Without pkg-config: typical Oracle MySQL + MariaDB header dirs.
            mysql_dep = declare_dependency(
                dependencies: mysql_lib,
                include_directories: [
                    include_directories('/usr/include/mysql', is_system: true),
                    include_directories('/usr/include/mariadb', is_system: true),
                ])
        endif
    endif
    if not mysql_dep.found()
        error('mysql_pcrf=true but MySQL/MariaDB client not found (pkg-config mysqlclient/libmariadb/mariadb or libmysqlclient)')
    endif
    mysql_cargs = ['-DHAVE_MYSQL']
    mysql_hdr_test = '''
#include <mysql.h>
int main(void) { return 0; }
'''
    if not cc.compiles(mysql_hdr_test,
            name : 'MySQL C API headers',
            args : mysql_cargs,
            dependencies : mysql_dep)
        error('mysql_pcrf=true needs mysql.h (MySQL or MariaDB C client headers). Debian/Ubuntu: sudo apt install libmariadb-dev OR default-libmysqlclient-dev (do not install both; MariaDB and Oracle MySQL -dev packages conflict).')
    endif
endif

libpcrf_sources = files('''
    pcrf-context.h
    pcrf-fd-path.h
    pcrf-event.h
    pcrf-sm.h
    metrics.h

    pcrf-init.c
    pcrf-context.c
    pcrf-event.c
    pcrf-sm.c

    pcrf-fd-path.c
    pcrf-gx-path.c
    pcrf-rx-path.c

    pcrf-mysql.h
    pcrf-mysql.c

    metrics.c
'''.split())

libpcrf = static_library('pcrf',
    sources : libpcrf_sources,
    dependencies : [libmetrics_dep,
                    libapp_dep,
                    libdbi_dep,
                    libdiameter_rx_dep,
                    libdiameter_gx_dep,
                    mysql_dep],
    c_args : mysql_cargs,
    install : false)

libpcrf_dep = declare_dependency(
    link_with : libpcrf,
    dependencies : [libmetrics_dep,
                    libapp_dep,
                    libdbi_dep,
                    libdiameter_rx_dep,
                    libdiameter_gx_dep,
                    mysql_dep])

pcrf_sources = files('''
    app-init.c
    ../main.c
'''.split())

executable('open5gs-pcrfd',
    sources : pcrf_sources,
    c_args : '-DDEFAULT_CONFIG_FILENAME="@0@/pcrf.yaml"'.format(open5gs_sysconfdir),
    include_directories : srcinc,
    dependencies : libpcrf_dep,
    install_rpath : libdir,
    install : true)
