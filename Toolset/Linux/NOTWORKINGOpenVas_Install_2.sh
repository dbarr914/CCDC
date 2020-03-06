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

update_nvt(){
/opt/gvm/bin/greenbone-nvt-sync
sudo openvas -u
}

gvmd_install(){
cd /opt/gvm/src/gvmd-9.0.0
sleep 1
export PKG_CONFIG_PATH=/opt/gvm/lib/pkgconfig:$PKG_CONFIG_PATH
sleep 1
mkdir build
sleep 1
cd build/
sleep 1
cmake -DCMAKE_INSTALL_PREFIX=/opt/gvm ..
sleep 1
make
sleep 1
make doc
sleep 1
make install
sleep 1
cd /opt/gvm/src
sleep 1
}

postgre_config(){
createuser -DRS gvm
createdb -O gvm gvmd

psql gvmd
create role dba with superuser noinherit;
grant dba to gvm;
create extension "uuid-ossp";
}

create_admin(){
gvm-manage-certs -agreenbone-certdata-sync
sleep 1
greenbone-scapdata-sync
sleep 3
gvmd --create-user=admin --password=admin
sleep 1
}

Update_IANA(){
xsltproc /opt/gvm/share/gvm/gvmd/portnames_update.xsl service-names-port-numbers.xml | sed "s/^<.*>$//g" | psql -v ON_ERROR_STOP=1 -q --pset pager=off --no-align -d gvmd -t
}

gsa_install(){
cd /opt/gvm/src/gsa-9.0.0
sleep 1
export PKG_CONFIG_PATH=/opt/gvm/lib/pkgconfig:$PKG_CONFIG_PATH
sleep 1
mkdir build
sleep 1
cd build/
sleep 1
cmake -DCMAKE_INSTALL_PREFIX=/opt/gvm ..
sleep 1
make
sleep 1
make doc
sleep 1
make install
sleep 1
touch /opt/gvm/var/log/gvm/gsad.log
sleep 1
cd /opt/gvm/src
sleep 1
}

ospd_installation(){
cd /opt/gvm/src
sleep 1
export PKG_CONFIG_PATH=/opt/gvm/lib/pkgconfig:$PKG_CONFIG_PATH
sleep 1
virtualenv --python python3.7  /opt/gvm/bin/ospd-scanner/
sleep 1
source /opt/gvm/bin/ospd-scanner/bin/activate
sleep 1
cd ospd-2.0.0
sleep 1
pip3 install .
sleep 1
cd /opt/gvm/src
sleep 1
cd ospd-openvas-1.0.0
sleep 1
pip3 install . 
sleep 1
cd /opt/gvm/src
sleep 1
}

start_up_scripts(){
cat << EOF > /etc/systemd/system/gvmd.service
[Unit]
Description=Job that runs the gvm daemon
Documentation=man:gvm
After=postgresql.service

[Service]
Type=forking
User=gvm
Group=gvm
PIDFile=/opt/gvm/var/run/gvmd.pid
WorkingDirectory=/opt/gvm
ExecStart=/opt/gvm/sbin/gvmd  --osp-vt-update=/opt/gvm/var/run/ospd.sock
Restart=on-failure
RestartSec=2min
KillMode=process
KillSignal=SIGINT
GuessMainPID=no
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

cat << EOF > /etc/systemd/system/gsad.service
[Unit]
Description=Job that runs the gsa daemon
Documentation=man:gsa
After=postgresql.service

[Service]
Type=forking
PIDFile=/opt/gvm/var/run/gsad.pid
WorkingDirectory=/opt/gvm
ExecStart=/opt/gvm/sbin/gsad --drop-privileges=gvm
Restart=on-failure
RestartSec=2min
KillMode=process
KillSignal=SIGINT
GuessMainPID=no
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

cat << EOF > /etc/systemd/system/ospd-openvas.service 
[Unit]
Description=Job that runs the ospd-openvas daemon
Documentation=man:gvm
After=postgresql.service

[Service]
Environment=PATH=/opt/gvm/bin/ospd-scanner/bin:/opt/gvm/bin:/opt/gvm/sbin:/opt/gvm/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Type=simple
User=gvm
Group=gvm
WorkingDirectory=/opt/gvm
PIDFile=/opt/gvm/var/run/ospd-openvas.pid
ExecStart=/opt/gvm/bin/ospd-scanner/bin/python /opt/gvm/bin/ospd-scanner/bin/ospd-openvas --pid-file /opt/gvm/var/run/ospd-openvas.pid --unix-socket=/opt/gvm/var/run/ospd.sock --log-file /opt/gvm/var/log/gvm/ospd-scanner.log
Restart=on-failure
RestartSec=2min
KillMode=process
KillSignal=SIGINT
GuessMainPID=no
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF
}

restart_services(){
systemctl daemon-reload
systemctl enable gvmd
systemctl enable gsad
systemctl enable ospd-openvas
systemctl start gvmd
systemctl start gsad
systemctl start ospd-openvas
}

create_scanner(){
gvmd --create-scanner="OPENVAS Scanner" --scanner-type="OpenVas" --scanner-host=/opt/gvm/var/run/ospd.sock
}


# Main body of script starts here
#
cd /opt/gvm/src
update_nvt
sleep 1
gvmd_install
sleep 1
sudo -u postgres bash
postgre_config
sleep 1
sudo su root
create_admin
sleep 1
Update_IANA
sleep 1
gsa_install
sleep 1
ospd_installation
sleep 1
start_up_scripts
sleep 1
restart_services
sleep 1
create_scanner

# Exit with an explicit status code
exit 0