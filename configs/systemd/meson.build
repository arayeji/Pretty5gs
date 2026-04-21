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

systemd_conf_in = '''
    open5gs-mmed.service
    open5gs-sgwcd.service
    open5gs-smfd.service
    open5gs-amfd.service
    open5gs-sgwud.service
    open5gs-upfd.service
    open5gs-hssd.service
    open5gs-pcrfd.service
    open5gs-nrfd.service
    open5gs-scpd.service
    open5gs-seppd.service
    open5gs-ausfd.service
    open5gs-udmd.service
    open5gs-pcfd.service
    open5gs-nssfd.service
    open5gs-bsfd.service
    open5gs-udrd.service
    open5gs-cgfd.service
    open5gs-admin-api.service
'''.split()

# Historically these were templated but not installed by `meson install`
# (Debian packaging copies them via debian/*.install instead). For the
# CGF daemon we install its unit directly so `meson install` is enough
# on non-Debian setups. The path /lib/systemd/system is canonical on
# Debian/Ubuntu; modern Fedora/Arch symlink it to /usr/lib/systemd/system
# so systemd still finds it.
systemd_unitdir = '/lib/systemd/system'

foreach file : systemd_conf_in
    # open5gs-cgfd is new; install it everywhere so operators don't
    # have to hand-copy the unit. The other units keep the legacy
    # behaviour (configured only, installed by debian/*.install) to
    # avoid disturbing existing .deb-based installs.
    do_install = (
            file == 'open5gs-cgfd.service' or
            file == 'open5gs-admin-api.service')
    if do_install
        configure_file(
                input : file + '.in',
                output : file,
                configuration : conf_data,
                install : true,
                install_dir : systemd_unitdir)
    else
        configure_file(
                input : file + '.in',
                output : file,
                configuration : conf_data)
    endif
endforeach

systemd_conf = '''
    99-open5gs.netdev
    99-open5gs.network        
'''.split()

foreach file : systemd_conf
    configure_file(
            input : file,
            output : file,
            configuration : conf_data)
endforeach

# Ship the env-file template next to the admin-api unit. It is NOT
# installed to /etc on purpose: the operator is expected to copy it
# to /etc/open5gs/admin-api.env, set a real OPEN5GS_ADMIN_TOKEN, and
# tighten the perms to 0640 root:open5gs. Installing it under
# /usr/share makes it discoverable from the service's Documentation=
# line and from packaging scripts without clobbering a site-edited
# copy on upgrade.
install_data(
        'open5gs-admin-api.env.example',
        install_dir : get_option('datadir') / 'open5gs/admin-api')
