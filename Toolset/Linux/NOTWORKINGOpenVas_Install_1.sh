#!/bin/bash
#
#
#
#
# -------------------------------
# -      Global  Variables      -
# -------------------------------




# -------------------------------
# -          Functions          -
# -------------------------------

install_openvas_deps(){
    sudo apt install software-properties-common
    sleep 3
    sudo add-apt-repository universe
    sleep 3
    sudo apt install -y cmake pkg-config libglib2.0-dev libgpgme11-dev libgnutls28-dev uuid-dev libssh-gcrypt-dev libldap2-dev doxygen graphviz libradcli-dev libhiredis-dev libpcap-dev bison libksba-dev libsnmp-dev gcc-mingw-w64 heimdal-dev libpopt-dev xmltoman redis-server xsltproc libical2-dev postgresql postgresql-contrib postgresql-server-dev-all gnutls-bin nmap rpm nsis curl wget fakeroot gnupg sshpass socat snmp smbclient libmicrohttpd-dev libxml2-dev python-polib gettext python3-paramiko python3-lxml python3-defusedxml python3-pip python3-psutil virtualenv
    sleep 5
    sudo apt install -y texlive-latex-extra --no-install-recommends
    sleep 5
    sudo apt install -y texlive-fonts-recommended
    sleep 5
    curl -sS https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add -
    sleep 3
    echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list
    sleep 3
    sudo apt update
    sleep 1
    sudo apt -y install yarn
    sleep 1
}

create_openvas_user(){
cp /etc/environment ~/environment.bak
sleep 1
sudo sed -i 's|PATH="|PATH="/opt/gvm/bin:/opt/gvm/sbin:/opt/gvm/.local/bin:|g' /etc/environment
sleep 1
cat << EOF > /etc/ld.so.conf.d/gvm.conf
# gmv 
libs
location/opt/gvm/lib
EOF
sleep 1
sudo mkdir /opt/gvm
sudo mkdir /opt/gvm/src
sleep 1
sudo adduser gvm --disabled-password --home /opt/gvm/ --no-create-home --gecos ''
sleep 1
sudo usermod -aG redis gvm  # This is for ospd-openvas can connect to redis.sock.. If you have a better idea here, pls write in the comments :) 
sudo chown gvm:gvm /opt/gvm/
sleep 1
cd /opt/gvm/src || exit
sleep 1
export PKG_CONFIG_PATH=/opt/gvm/lib/pkgconfig:$PKG_CONFIG_PATH
sleep 1
}

download_openvas_source(){
wget -O gvm-libs-11.0.0.tar.gz  https://github.com/greenbone/gvm-libs/archive/v11.0.0.tar.gz
sleep 1
wget -O openvas-7.0.0.tar.gz https://github.com/greenbone/openvas/archive/v7.0.0.tar.gz
sleep 1
wget -O gvmd-9.0.0.tar.gz https://github.com/greenbone/gvmd/archive/v9.0.0.tar.gz
sleep 1
wget -O openvas-smb-1.0.5.tar.gz https://github.com/greenbone/openvas-smb/archive/v1.0.5.tar.gz
sleep 1
wget -O gsa-9.0.0.tar.gz https://github.com/greenbone/gsa/archive/v9.0.0.tar.gz
sleep 1
wget -O ospd-openvas-1.0.0.tar.gz https://github.com/greenbone/ospd-openvas/archive/v1.0.0.tar.gz
sleep 1
wget -O ospd-2.0.0.tar.gz https://github.com/greenbone/ospd/archive/v2.0.0.tar.gz
sleep 1
}

extract_source_code(){
find . -name \*.gz -exec tar zxvfp {} \;
}

gvm-libs_install(){
cd gvm-libs-11.0.0 || exit
sleep 1
export PKG_CONFIG_PATH=/opt/gvm/lib/pkgconfig:$PKG_CONFIG_PATH
sleep 1
mkdir build
sleep 1
cd build || exit
sleep 1
cmake -DCMAKE_INSTALL_PREFIX=/opt/gvm ..
sleep 1
make
sleep 1
make doc
sleep 1
make install
sleep 1
cd /opt/gvm/src || exit
sleep 1
}

openvas-smb_install(){
cd openvas-smb-1.0.5 || exit
export PKG_CONFIG_PATH=/opt/gvm/lib/pkgconfig:$PKG_CONFIG_PATH 
mkdir build
cd build/ || exit
cmake -DCMAKE_INSTALL_PREFIX=/opt/gvm ..
make
make install 
cd /opt/gvm/src || exit
}

scanner_build(){
cd openvas-7.0.0 || exit
export PKG_CONFIG_PATH=/opt/gvm/lib/pkgconfig:$PKG_CONFIG_PATH 
mkdir build
cd build/ || exit
cmake -DCMAKE_INSTALL_PREFIX=/opt/gvm .. 
make
make doc
make install
cd /opt/gvm/src || exit
}

install_redis(){
ldconfig
cp /etc/redis/redis.conf /etc/redis/redis.orig
cp /opt/gvm/src/openvas-7.0.0/config/redis-openvas.conf /etc/redis/
chown redis:redis /etc/redis/redis-openvas.conf
echo "db_address = /run/redis-openvas/redis.sock" > /opt/gvm/etc/openvas/openvas.conf
systemctl enable redis-server@openvas.service
systemctl start redis-server@openvas.service
}

edit_sysctlconf(){
sysctl -w net.core.somaxconn=1024sysctl vm.overcommit_memory=1\&nbsp;
echo "net.core.somaxconn=1024"&nbsp; >> /etc/sysctl.conf
echo "vm.overcommit_memory=1" >> /etc/sysctl.conf
}

disable_thp(){
cat << EOF > /etc/systemd/system/disable-thp.service
[Unit]
Description=Disable Transparent Huge Pages (THP)

[Service]
Type=simple
ExecStart=/bin/sh -c "echo 'never' > /sys/kernel/mm/transparent_hugepage/enabled && echo 'never' > /sys/kernel/mm/transparent_hugepage/defrag"

[Install]
WantedBy=multi-user.target
EOF
}

reload_daemons(){
systemctl daemon-reload
sleep 1
systemctl start disable-thp
sleep 1
systemctl enable disable-thp
sleep 1
systemctl restart redis-server
sleep 1
}

edit_visudo(){
echo -e "################_Important Note_################"
echo -e " You need to edit the visudo file with the following:"
echo 
echo "---------------------------------------------------------------------------------------------------------------------"
echo
echo -e 'Defaults        secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin:/opt/gvm/sbin"'
echo
echo -e "### Allow the user running ospd-openvas, to launch openvas with root permissions
gvm ALL = NOPASSWD: /opt/gvm/sbin/openvas\n
gvm ALL = NOPASSWD: /opt/gvm/sbin/gsad\n"
echo
echo "---------------------------------------------------------------------------------------------------------------------"
echo
echo -e 'We have reached the end of the first installation script.'
echo -e 'Run OpenVas_Install_2 to continue'
echo -e 'Thank you!'
}


# Main body of script starts here
#
#

install_openvas_deps
sleep 1
create_openvas_user
sleep 1
download_openvas_source
sleep 1
extract_source_code
sleep 1
gvm-libs_install
sleep 1
openvas-smb_install
sleep 1
scanner_build
sleep 1
install_redis
sleep 1
edit_sysctlconf
sleep 1
disable_thp
sleep 1
reload_daemons
sleep 1
edit_visudo

# Exit with an explicit status code
exit 0