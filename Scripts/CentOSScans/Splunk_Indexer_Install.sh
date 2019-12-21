#!/bin/bash
# Bash install script for Pace CCDC Team CentOS Splunk Indexer
# Version 1.0.2
# Written by Daniel Barr
# 
# ---------------------------------------------------------------------
# Free to use by all teams. Please realize you are using this script
# at your own risk. The author holds no liability and will not be held
# responsible for any damages done to systems or system configurations.
# ---------------------------------------------------------------------
# This script will install OSQUERY 4.0.2 endpoint visibility agent,
# and SPLUNK INDEXER and other dependencies. In addition it will download 
# the predetermined configuration files.
# ---------------------------------------------------------------------
# Take note these configurations may need to be adjusted by the user as
# needed. Every environment is different and should be treated as such.
# ---------------------------------------------------------------------
# The goal of this install script is to efficiently deploy the necessary
# tool-sets for effective system monitoring during the Collegiate Cyber
# Defense Competition. This tool-set represents a larger overall strategy
# and should be tailored to your specific team.
#
#                         DEPENDENCY INSTALL
# ---------------------------------------------------------------------
#
# Install GITHUB, WGET, LSB_RELEASE, NMAP
#
yum clean all
yum -y update
yum -y install git wget redhat-lsb-core nmap yum-utils lsof epel-release
#
#                         SPLUNK INDEXER INSTALL
# ---------------------------------------------------------------------
#
disable_hugh_pages(){ 
 echo "never" > /sys/kernel/mm/transparent_hugepage/enabled
 echo "never" > /sys/kernel/mm/transparent_hugepage/defrag
 echo "[Unit]" > /etc/systemd/system/disable-thp.service
 echo "Description=Disable Transparent Huge Pages" >> /etc/systemd/system/disable-thp.service
 echo "" >> /etc/systemd/system/disable-thp.service
 echo "[Service]" >> /etc/systemd/system/disable-thp.service
 echo "Type=simple" >> /etc/systemd/system/disable-thp.service
 echo 'ExecStart=/bin/sh -c "echo never > /sys/kernel/mm/transparent_hugepage/enabled && echo never > /sys/kernel/mm/transparent_hugepage/defrag"' >> /etc/systemd/system/disable-thp.service
 echo "Type=simple" >> /etc/systemd/system/disable-thp.service
 echo "" >> /etc/systemd/system/disable-thp.service
 echo "[Install]" >> /etc/systemd/system/disable-thp.service
 echo "WantedBy=multi-user.target" >> /etc/systemd/system/disable-thp.service
 systemctl daemon-reload
 systemctl start disable-thp
 systemctl enable disable-thp
 echo
 echo "[*] Transparent Huge Pages (THP) Disabled."
 echo
}

increase_ulimit(){
 ulimit -n 64000
 ulimit -u 20480
 echo "DefaultLimitFSIZE=-1" >> /etc/systemd/system.conf
 echo "DefaultLimitNOFILE=64000" >> /etc/systemd/system.conf
 echo "DefaultLimitNPROC=20480" >> /etc/systemd/system.conf
 echo
 echo "[*] Increasing ulimit..."
 echo "[*] ulimit Increased."
 echo
}

download_splunk(){
 cd /tmp
 echo
 echo "[*] Downloading Splunk....."
 wget -O splunkforwarder-8.0.0-1357bef0a7f6-linux-2.6-x86_64.rpm 'https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=linux&version=8.0.0&product=universalforwarder&filename=splunkforwarder-8.0.0-1357bef0a7f6-linux-2.6-x86_64.rpm&wget=true'
 echo
 echo "[*] Splunk Downloaded."
 echo
 }

install_splunk(){
 echo "[*] Installing Splunk....."
 tar -xzvf /tmp/splunk-7.3.0-657388c7a488-Linux-x86_64.tgz -C /opt
 echo
 echo "[*] Splunk Installed."
 rm -f /tmp/splunk-7.3.0-657388c7a488-Linux-x86_64.tgz
}

add_user(){
 useradd -r splunk
 chown -R splunk:splunk /opt/splunk
 echo
 echo "Creating Splunk User....."
 echo "Splunk User Created."
 echo
} 
 
enable_ssl(){ 
 echo "[settings]" > /opt/splunk/etc/system/local/web.conf
 echo "enableSplunkWebSSL = true" >> /opt/splunk/etc/system/local/web.conf
 echo
 echo "[*] Enabling SSL....."
 echo "[*] SSL enabled for Splunk Web using self-signed certificate."
 echo
}

firewall_rules(){
 echo "[*] Opening Splunk firewall ports....."
 echo
 afz=`firewall-cmd --get-active-zone | head -1`
 firewall-cmd --zone=$afz --add-port=8000/tcp --permanent
 firewall-cmd --zone=$afz --add-port=8065/tcp --permanent
 firewall-cmd --zone=$afz --add-port=8089/tcp --permanent
 firewall-cmd --zone=$afz --add-port=8191/tcp --permanent
 firewall-cmd --zone=$afz --add-port=9997/tcp --permanent
 firewall-cmd --zone=$afz --add-port=8080/tcp --permanent
 firewall-cmd --reload
 echo
 echo "[*] Firewall ports opened."
 echo
}

adjust_inputs(){
 echo
 echo "[*] Adding receiver to configuration files....."
 echo
 echo "[splunktcp]" > /opt/splunk/etc/system/local/inputs.conf
 echo "[splunktcp://9997]" >> /opt/splunk/etc/system/local/inputs.conf
 echo "index = main" >> /opt/splunk/etc/system/local/inputs.conf
 echo "disabled = 0" >> /opt/splunk/etc/system/local/inputs.conf
 echo "" >> /opt/splunk/etc/system/local/inputs.conf
 echo
 echo "[*] Enabled Splunk TCP input over 9997."
}

mitigate_privs(){
 chown splunk:splunk /opt/splunk/etc/system/local/inputs.conf
 echo
 echo "[*] Running test start....."
 echo "[*] Complete."
 echo
 echo "[*] Enabling Splunk to start at boot....."
 echo "[*] Complete."
 echo
 echo "[*] Adjusting splunk-launch.conf to mitigate privilege escalation attack....."
 echo "[*] Complete."
 echo
 runuser -l splunk -c '/opt/splunk/bin/splunk start --accept-license'
 /opt/splunk/bin/splunk enable boot-start -user splunk
 runuser -l splunk -c '/opt/splunk/bin/splunk stop'
 chown root:splunk /opt/splunk/etc/splunk-launch.conf
 chmod 644 /opt/splunk/etc/splunk-launch.conf
 echo
 echo
}


splunk_check(){
 if [[ -f /opt/splunk/bin/splunk ]]
         then
                 echo Splunk Enterprise
                 cat /opt/splunk/etc/splunk.version | head -1
                 echo "has been installed, configured, and started!"
                 echo "Visit the Splunk server using https://hostNameORip:8000 as mentioned above."
                 echo
                 echo
                 echo "                        HAPPY SPLUNKING!!!"
                 echo
                 echo
                 echo
         else
                 echo Splunk Enterprise has FAILED install!
 fi
}
 
 
disable_hugh_pages 
increase_ulimit
download_splunk
install_splunk
add_user
# enable_ssl
firewall_rules
adjust_inputs
mitigate_privs
runuser -l splunk -c '/opt/splunk/bin/splunk start'
splunk_check

#                            OSQUERY INSTALL
# ---------------------------------------------------------------------
cd /tmp
wget https://pkg.osquery.io/rpm/osquery-4.1.1-1.linux.x86_64.rpm
rpm -i osquery-4.1.1-1.linux.x86_64.rpm

#                        CONFIGURATION DOWNLOADS
# ---------------------------------------------------------------------





