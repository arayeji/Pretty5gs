sudo systemctl stop open5gs-hssd.service open5gs-smfd.service open5gs-upfd.service open5gs-mmed.service open5gs-sgwcd.service open5gs-sgwud.service

sudo meson setup --reconfigure build
sudo rm -rf build/
sudo meson build
sudo ninja -C build
sudo ninja -C build install
sudo meson setup --reconfigure build
sudo rm -rf build/
sudo meson build --prefix=/usr/local
sudo ninja -C build
sudo ninja -C build install

sudo meson configure build -Dprefix=/usr          # only if not already /usr
sudo ninja -C build install

sudo ldconfig



sudo systemctl restart open5gs-hssd.service open5gs-smfd.service open5gs-upfd.service open5gs-mmed.service open5gs-sgwcd.service open5gs-sgwud.service
