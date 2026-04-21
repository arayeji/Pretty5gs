sudo systemctl stop open5gs-hssd.service open5gs-smfd.service open5gs-upfd.service open5gs-mmed.service open5gs-sgwcd.service open5gs-sgwud.service  open5gs-cgfd.service

sudo meson setup --reconfigure build
sudo meson configure build -Dadmin_watcher=true
sudo rm -rf build/
sudo meson build
sudo ninja -C build
sudo ninja -C build install
sudo meson setup --reconfigure build
sudo rm -rf build/
sudo meson build --prefix=/usr/local
sudo ninja -C build
sudo ninja -C build install

sudo meson configure build -Dprefix=/usr -Dadmin_watcher=true
sudo ninja -C build install

sudo ldconfig



sudo systemctl restart open5gs-hssd.service open5gs-smfd.service open5gs-upfd.service open5gs-mmed.service open5gs-sgwcd.service open5gs-sgwud.service open5gs-cgfd.service
