#!/bin/bash

# Global Variables

read -p "What is the username for the openvas admin user? " ADMINUSER
read -p "What is the passphrase for the openvas admin user? " ADMINPASS

# Check root
check_root(){
if [[ "$EUID" -ne 0 ]]; then
    echo
    echo "[!] This installer must be run as root."
    echo "[!] Please use sudo or switch to the root user"
    echo
    exit
else
continue
fi
}

# Download the necessary dependencies.

start_deps(){
cd /usr/local/src
sudo mkdir gvm10
sudo chown $USER:$USER gvm10                #Change ownership to new sudo user "gvm"
cd gvm10
}

install_requirements(){
apt install software-properties-common ;\
add-apt-repository universe ;\
apt install -y cmake pkg-config libglib2.0-dev libgpgme11-dev uuid-dev libssh-gcrypt-dev libhiredis-dev \
gcc libgnutls28-dev libpcap-dev libgpgme-dev bison libksba-dev libsnmp-dev libgcrypt20-dev redis-server \
libsqlite3-dev libical-dev gnutls-bin doxygen nmap libmicrohttpd-dev libxml2-dev apt-transport-https curl \
xmltoman xsltproc gcc-mingw-w64 perl-base heimdal-dev libpopt-dev graphviz nodejs rpm nsis wget sshpass \
socat snmp gettext python-polib git ;\
curl --silent --show-error https://dl.yarnpkg.com/debian/pubkey.gpg | sudo apt-key add - ;\
echo "deb https://dl.yarnpkg.com/debian/ stable main" | sudo tee /etc/apt/sources.list.d/yarn.list ;\
sudo apt-get update ;\
sudo apt-get install yarn
}

# Download the OpenVas 10.
download_magic(){
wget -O gvm-libs-10.0.0.tar.gz https://github.com/greenbone/gvm-libs/archive/v10.0.0.tar.gz ;\
wget -O openvas-scanner-6.0.0.tar.gz https://github.com/greenbone/openvas-scanner/archive/v6.0.0.tar.gz;\
wget -O gvmd-8.0.0.tar.gz https://github.com/greenbone/gvmd/archive/v8.0.0.tar.gz ;\
wget -O gsa-8.0.0.tar.gz https://github.com/greenbone/gsa/archive/v8.0.0.tar.gz ;\
wget -O openvas-smb-1.0.5.tar.gz https://github.com/greenbone/openvas-smb/archive/v1.0.5.tar.gz ;\
wget -O ospd-1.3.2.tar.gz https://github.com/greenbone/ospd/archive/v1.3.2.tar.gz 
}

# Upack the previously downloaded tarball files.
unpack_tarballs(){
find . -name \*.gz -exec tar zxvfp {} \;
}

install_gvm-libs(){
cd gvm-libs-10.0.0 ;\
mkdir build ;\
cd build ;\
cmake .. ;\
make ;\
make doc-full ;\
make install ;\
cd /usr/local/src/gvm10
}

build_openvas-smb(){
cd openvas-smb-1.0.5 ;\
mkdir build ;\
cd build/ ;\
cmake .. ;\
make ;\
make install ;\
cd /usr/local/src/gvm10
}

build_scanner(){
cd openvas-6.0.0 ;\
mkdir build ;\
cd build/ ;\
cmake .. ;\
make ;\
make doc-full ;\
make install ;\
cd /usr/local/src/gvm10
}

fix_redis_A(){
cp /etc/redis/redis.conf /etc/redis/redis.orig ;\
cp /usr/local/src/gvm10/openvas-scanner-6.0.0/build/doc/redis_config_examples/redis_4_0.conf /etc/redis/redis.conf ;\
sed -i 's|/usr/local/var/run/openvas-redis.pid|/var/run/redis/redis-server.pid|g' /etc/redis/redis.conf ;\
sed -i 's|/tmp/redis.sock|/var/run/redis/redis-server.sock|g' /etc/redis/redis.conf ;\
sed -i 's|dir ./|dir /var/lib/redis|g' /etc/redis/redis.conf
}

fix_redis_B(){
sysctl -w net.core.somaxconn=1024
sysctl vm.overcommit_memory=1
echo "net.core.somaxconn=1024"  >> /etc/sysctl.conf
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

reload_daemon(){
systemctl daemon-reload ;\
systemctl start disable-thp ;\
systemctl enable disable-thp ;\
systemctl restart redis-server
}

edit_config_A(){
cat << EOF > /usr/local/etc/openvas/openvassd.conf
db_address = /var/run/redis/redis-server.sock
EOF
}

update_nvts(){
greenbone-nvt-sync
}

reload_modules(){
ldconfig
}

start_openvassd(){
openvassd
}

check_openvassd(){
watch "ps -ef | grep openvassd"
}

build_gvmanager(){
cd gvmd-8.0.0 ;\
mkdir build ;\
cd build/ ;\
cmake .. ;\
make ;\
make doc-full ;\
make install ;\
cd /usr/local/src/gvm10
}

install_gsa(){
cd gsa-8.0.0 ;\
sed -i 's/#ifdef GIT_REV_AVAILABLE/#ifdef GIT_REVISION/g' ./gsad/src/gsad.c ;\
sed -i 's/return root.get_result.commands_response.get_results_response.result/return root.get_result.get_results_response.result/g' ./gsa/src/gmp/commands/results.js ;\
mkdir build ;\
cd build/ ;\
cmake .. ;\
make ;\
make doc-full ;\
make install ;\
cd /usr/local/src/gvm10
}


fix_certs(){
gvm-manage-certs -a
}

create_admin(){
gvmd --create-user="$ADMINUSER" --new-password="$ADMINPASS"
}

start_system(){
gvmd ;\
openvassd ;\
gsad
}


check_root
start_deps
install_requirements
download_magic
unpack_tarballs
install_gvm-libs
build_openvas-smb
build_scanner
fix_redis_A
fix_redis_B
disable_thp
reload_daemon
edit_config_A
update_nvts
reload_modules
start_openvassd
check_openvassd
sleep 10
build_gvmanager
install_gsa
fix_certs
create_admin
start_system
