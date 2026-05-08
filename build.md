sudo systemctl stop open5gs-hssd.service open5gs-smfd.service open5gs-upfd.service open5gs-mmed.service open5gs-sgwcd.service open5gs-sgwud.service  open5gs-cgfd.service

# Clean configure only if switching prefix or Meson options (otherwise use --reconfigure below).
sudo rm -rf build/

# Meson needs mysql_pcrf declared in repo-root meson_options.txt or -Dmysql_pcrf=true fails.
# Run once per tree if the line is missing (safe to repeat):
grep -qF "option('mysql_pcrf'" meson_options.txt || printf '%s\n' "option('mysql_pcrf', type: 'boolean', value: false, description: 'Link PCRF with libmysqlclient for PyHSS MySQL policy (subscriber+apn)')" >> meson_options.txt

sudo meson setup build --prefix=/usr -Dmysql_pcrf=true
# Existing build/ tree: sudo meson setup build --reconfigure --prefix=/usr -Dmysql_pcrf=true
# (same meson_options.txt requirement as above)

sudo ninja -C build
sudo ninja -C build install

sudo ldconfig

sudo systemctl restart  open5gs-smfd.service open5gs-mmed.service open5gs-sgwcd.service 

################################################################################
# Added: PCRF + PyHSS MySQL
################################################################################
#
# The meson lines above use -Dmysql_pcrf=true; that requires the option() line in
# meson_options.txt (see grep/printf block before meson setup). Omit the -D flag to
# build without linking libmysqlclient, or use -Dmysql_pcrf=false.
#
# Debian/Ubuntu — MySQL C client headers (pick ONE; libmariadb-dev conflicts with default-libmysqlclient-dev):
#   sudo apt install libmariadb-dev
#   OR: sudo apt install default-libmysqlclient-dev
#
# Config: edit pcrf.yaml — uncomment pcrf.mysql (same DB as PyHSS: server, user,
# password, database). Comment out db_uri if you do not use Open5GS Mongo for PCRF
# subscriber data. YAML pcrf.policy is checked first; MySQL is used when no policy
# matches the UE. PyHSS: subscriber.apn_list must include the APN name; apn row
# must exist with matching apn.apn (qos + apn_ambr_dl / apn_ambr_ul).
################################################################################
