#!/bin/bash
#
# Bash Install script for CCDC Team Linux Environments
# Version 2.0.8
# Written by Daniel Barr
#
# ---------------------------------------------------------------------
# Free to use by all teams. Please realize you are using this script
# at your own risk. The author holds no liability and will not be held
# responsible for any damages done to systems or system configurations.
# ---------------------------------------------------------------------
# This script should be used on any Linux system using the appropriate
# command arguments. It will update, upgrade, and install the necessary 
# components that we have outlined as a team.
# ---------------------------------------------------------------------
# The goal of this install script is to efficiently install relavant
# system tools quickly for effective system monitoring during the Collegiate Cyber
# Defense Competition. This tool-set represents a larger overall strategy
# and should be tailored to your specific team.
#
#
# -------------------------------
# -      Global  Variables      -
# -------------------------------

SPLUNK_INDEXER_LOCATION='https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=linux&version=8.0.1&product=splunk&filename=splunk-8.0.1-6db836e2fb9e-Linux-x86_64.tgz&wget=true'
SPLUNK_FORWARDER_LOCATION='https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=linux&version=8.0.1&product=universalforwarder&filename=splunkforwarder-8.0.1-6db836e2fb9e-Linux-x86_64.tgz&wget=true'
OSQUERY_DEB_LOCATION='https://pkg.osquery.io/deb/osquery_4.1.1_1.linux.amd64.deb'
OSQUERY_RPM_LOCATION='https://pkg.osquery.io/rpm/osquery-4.1.1-1.linux.x86_64.rpm'

# -------------------------------
# -    Formatting  Variables    -
# -------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
PURPLE='\033[0;35m'
BLUE='\033[0;36m'
NC='\033[0m'

# -------------------------------
# -          Functions          -
# -------------------------------

# Downloads and Installs the necessary dependencies on Debian based systems, then upgrades the system.
dependency_install_deb(){
 echo
 echo -e "${GREEN}[*] Installing Dependencies...${NC}"
 echo
 sudo apt-get install -y lsof nmap clamav debsums fail2ban git sqlite3
 sleep 5
 echo
 echo -e "${YELLOW}[*] Complete.\e[0m"
 echo
 echo -e "${BLUE}Updating System...${NC}"
 echo -e "${BLUE}This may take some time...${NC}"
 echo
 sudo apt-get update
 sudo apt-get upgrade
 echo
 if [ "$?" -eq "0" ]
 then
    sleep 5
    echo -e "${YELLOW}[*] Complete.${NC}"
    echo
 else
    sleep 5
    echo -e "${RED}[!] Update not successful.${NC}"
    echo
 fi
 echo
 echo -e "${GREEN}Downloading Configs...${NC}"
 echo
 mkdir /tmp/CCDC-Setup/
 cd /tmp/CCDC-Setup/ || exit
 git clone https://github.com/dbarr914/CCDC.git
 if [ "$?" -eq "0" ]
 then
    echo
    echo -e "${YELLOW}[*] Download Complete.\e[0m"
 else
    echo
    echo -e "${RED}[!] Download not successful."
 fi
}

# Downloads and Installs the necessary dependencies on Red-Hat based systems, then upgrades the system.
dependency_install_rpm(){
 echo -e "${GREEN}[*] Cleaning up repo cache...${NC}"
 sudo yum clean all | tee 'install.file'
 echo
 echo -e "${YELLOW}[*] Complete.${NC}"
 echo
 echo -e "${GREEN}[*] Installing Dependencies...${NC}"
 echo
 sudo yum -y install git auditd wget redhat-lsb-core nmap yum-utils lsof epel-release | tee -a 'install.file'
 sleep 5
 echo
 echo -e "${YELLOW}[*] Complete.${NC}"
 echo
 echo -e "${BLUE}Updating System...${NC}"
 echo -e "${BLUE}This may take some time...${NC}"
 sudo yum -y update
 if [ "$?" -eq "0" ]
 then
    echo -e "${YELLOW}[*] Complete.${NC}"
    
 else
    echo -e "${RED}[!] Update not successful.${NC}"
    
 fi
 echo
 echo -e "${GREEN}Downloading Configs...${NC}"
 mkdir /tmp/CCDC-Setup/
 cd /tmp/CCDC-Setup/ || exit
 git clone https://github.com/dbarr914/CCDC.git
 if [ "$?" -eq "0" ]
 then
    echo -e "${YELLOW}[*] Complete.${NC}"
    
 else
    echo -e "${RED}[!] Download not successful.${NC}"
    
 fi
}

#         Splunk Functions
# -------------------------------

# Disables page limits, recommended in splunk documentation
disable_hugh_pages_indexer(){
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
 echo -e "${YELLOW}[*] Transparent Huge Pages (THP) Disabled.${NC}"
 echo
}

# Increase the i/o limits of the indexing server
increase_ulimit_indexer(){
 echo -e "${GREEN}[*] Increasing ulimit...${NC}"
 echo
 ulimit -n 64000
 ulimit -u 20480
 echo "DefaultLimitFSIZE=-1" >> /etc/systemd/system.conf
 echo "DefaultLimitNOFILE=64000" >> /etc/systemd/system.conf
 echo "DefaultLimitNPROC=20480" >> /etc/systemd/system.conf
 echo
 echo -e "${YELLOW}[*] ulimit Increased.${NC}"
 echo
}

# Enables ssl on splunk indexer
enable_ssl_indexer(){
 echo -e "${GREEN}[*] Enabling SSL.....${NC}"
 echo
 echo "[settings]" > /opt/splunk/etc/system/local/web.conf
 echo "enableSplunkWebSSL = true" >> /opt/splunk/etc/system/local/web.conf
 echo
 echo -e "${YELLOW}[*] SSL enabled for Splunk Web using self-signed certificate.${NC}"
 echo
}

# Will enable SSL on the Forwarder.....Needs more work. This is not correct. 
# See https://docs.splunk.com/Documentation/Splunk/8.0.1/Security/ConfigureSplunkforwardingtousesignedcertificates
# enable_ssl_forwarder(){
#  echo "[*] Enabling SSL....."
#  echo
#  echo "[settings]" > /opt/splunkforwarder/etc/system/local/web.conf
#  echo "enableSplunkWebSSL = true" >> /opt/splunkforwarder/etc/system/local/web.conf
#  echo
#  echo -e "${YELLOW}[*] SSL enabled for Splunk-Forwarder using self-signed certificate.\e[0m"
#  echo
# }

# Downloads and Installs the Splunk Indexer
install_splunk_indexer(){
 cd /tmp || exit

 echo -e "${GREEN}[*] Downloading Splunk.....${NC}"
 echo
 wget -O splunk-8.tgz "$SPLUNK_INDEXER_LOCATION"
 echo
 echo -e "${YELLOW}[*] Splunk Downloaded.${NC}"
 echo
 echo -e "${GREEN}[*] Installing Splunk.....${NC}"
 echo
 tar -xzvf /tmp/splunk-8.tgz -C /opt | tee -a 'install.file'
 echo
 echo -e "${YELLOW}[*] Splunk Enterprise Installed.${NC}"
 echo
}

# Downloads and Installs the Splunk Universal Forwarder
install_splunk_forwarder(){
 cd /tmp || exit
 echo
 echo -e "${GREEN}[*] Downloading Splunk Universal Forwarder.....${NC}"
 wget -O splunkforwarder-8.tgz "$SPLUNK_FORWARDER_LOCATION"
 echo
 echo -e "${YELLOW}[*] Splunk UFW Downloaded.${NC}"
 echo
 echo -e "${GREEN}[*] Installing Splunk Universal Forwarder.....${NC}"
 sudo tar -xzvf /tmp/splunkforwarder-8.tgz -C /opt
 echo
 echo -e "${YELLOW}[*] Splunk UFW Installed.${NC}"
}

# Adds the splunk user and changes the ownership of the splunk files to said user.
add_splunk_user_forwarder(){
 echo -e "${GREEN}[*] Creating Splunk User.....${NC}"
 useradd splunk
 chown -R splunk:splunk /opt/splunkforwarder
 echo
 echo -e "${YELLOW}[*] Splunk User Created.${NC}"
 echo
}

add_splunk_user_indexer(){
 echo
 echo -e "${GREEN}[*] Creating Splunk User.....${NC}"
 useradd splunk
 chown -R splunk:splunk /opt/splunk
 echo
 echo -e "${YELLOW}[*] Splunk User Created.${NC}"
 echo
}

# Performs the initial run of the Splunk indexer. User's will need to 
# input the Splunk Administrative Username and Passphrase.
initial_run_indexer(){
 echo
 echo -e "${GREEN}[*] Running initial start.....${NC}"
 echo
 sudo /opt/splunk/bin/splunk start --accept-license
 sleep 2
 sudo /opt/splunk/bin/splunk stop | tee -a 'install.file'
 echo
 echo -e "${YELLOW}[*] Complete.${NC}"
 echo
 echo -e "${GREEN}[*] Enabling Splunk to start at boot.....${NC}"
 echo
 sudo /opt/splunk/bin/splunk enable boot-start
 echo
 echo -e "${YELLOW}[*] Complete.${NC}"
 echo
}

# Performs the initial run of the Splunk Forwarder. User's will need to 
# input the Splunk Administrative Username and Passphrase.
initial_run_forwarder(){
 echo
 echo -e "${GREEN}[*] Running initial start.....${NC}"
 echo
 sudo /opt/splunkforwarder/bin/splunk start --accept-license
 sleep 2
 sudo /opt/splunkforwarder/bin/splunk stop | tee -a 'install.file'
 echo
 echo -e "${YELLOW}[*] Complete.${NC}"
 echo
 echo -e "${GREEN}[*] Enabling Splunk-Forwarder to start at boot.....${NC}"
 echo
 sudo /opt/splunkforwarder/bin/splunk enable boot-start
 echo
 echo -e "${YELLOW}[*] Complete.${NC}"
 echo
}

#Checks to see if Splunk binary is located in the /opt/splunk/bin directory.
splunk_indexer_check(){
 if [[ -f /opt/splunk/bin/splunk ]]
         then
                echo -e "${GREEN}"
                echo "Splunk Enterprise $(cat /opt/splunk/etc/splunk.version | head -1) has been installed, configured, and started!"
                echo
                echo "Visit the Splunk server using https://hostNameORip:8000 as mentioned above."
                echo
                echo "                        HAPPY SPLUNKING!!!"
                echo
                echo -e "${NC}"
         else
                echo
                echo -e "${RED}[!]Splunk Enterprise has FAILED install!${NC}"
                echo
 fi
}

splunk_forwarder_check(){
 if [[ -f /opt/splunkforwarder/bin/splunk ]]
         then
                echo -e "${GREEN}"
                echo "Splunk Universal Forwarder $(cat /opt/splunkforwarder/etc/splunk.version | head -1) is installed!"
                echo
                echo "Verify your inputs & outputs.conf files located in /opt/splunkforwarder/etc/system/local/ directory."
                echo
                echo "                        HAPPY SPLUNKING!!!"
                echo -e "${NC}"
                 
         else
                echo
                echo -e "${RED}[!]Splunk Universal Forwarder is NOT installed!${NC}"
                echo
 fi
}
#         Firewall Rules
# -------------------------------

# Configures Indexer Specific firewall rules on Debian Based systems using UFW.
indexer_firewall_rules_deb(){
 echo -e "${GREEN}[*] Opening Splunk firewall ports.....${NC}"
 echo
 sudo ufw default allow outgoing
 echo -e "${BLUE}[*] Opening port 8000...${NC}${GREEN}"
 echo
 sudo ufw allow 8000
 echo
 echo -e "${NC}${BLUE}[*] Opening port 8065...${NC}${GREEN}"
 echo
 sudo ufw allow 8065
 echo
 echo -e "${NC}${BLUE}[*] Opening port 8089...${NC}${GREEN}"
 echo
 sudo ufw allow 8089
 echo
 echo -e "${NC}${BLUE}[*] Opening port 8191...${NC}${GREEN}"
 echo
 sudo ufw allow 8191
 echo
 echo -e "${NC}${BLUE}[*] Opening port 9997...${NC}${GREEN}"
 echo
 sudo ufw allow 9997
 echo
 echo -e "${NC}${BLUE}[*] Opening port 8080...${NC}${GREEN}"
 echo
 sudo ufw allow 8080
 echo
 echo -e "${NC}${BLUE}[*] Opening port 514...${NC}${GREEN}"
 echo
 sudo ufw allow 514
 echo
 echo -e "${YELLOW}[*] Firewall ports opened.${NC}"
 echo
 echo -e "${GREEN}[*] Enabling Firewall..."
 echo
 sudo ufw enable
 echo -e "${NC}"
}

# Configures Indexer Specific firewall rules on CentOS Based systems using Firewall-cmd.
indexer_firewall_rules_rpm(){
 echo -e "${GREEN}[*] Opening Splunk firewall ports.....${NC}"
 echo
 afz=$(firewall-cmd --get-active-zone | head -1)
 echo -e "${BLUE}[*] Opening port 8000...${NC}${GREEN}"
 echo
 firewall-cmd --zone="$afz" --add-port=8000/tcp --permanent
 echo
 echo -e "${NC}${BLUE}[*] Opening port 8065...${NC}${GREEN}"
 echo
 firewall-cmd --zone="$afz" --add-port=8065/tcp --permanent
 echo
 echo -e "${NC}${BLUE}[*] Opening port 8089...${NC}${GREEN}"
 echo
 firewall-cmd --zone="$afz" --add-port=8089/tcp --permanent
 echo
 echo -e "${NC}${BLUE}[*] Opening port 8191...${NC}${GREEN}"
 echo
 firewall-cmd --zone="$afz" --add-port=8191/tcp --permanent
 echo
 echo -e "${NC}${BLUE}[*] Opening port 9997...${NC}${GREEN}"
 echo
 firewall-cmd --zone="$afz" --add-port=9997/tcp --permanent
 echo
 echo -e "${NC}${BLUE}[*] Opening port 8080...${NC}${GREEN}"
 echo
 firewall-cmd --zone="$afz" --add-port=8080/tcp --permanent
 echo
 echo -e "${NC}${BLUE}[*] Opening port 514...${NC}${GREEN}"
 echo
 firewall-cmd --zone="$afz" --add-port=514/udp --permanent
 echo
 echo -e "${GREEN}[*] Reloading Firewall...${NC}${GREEN}"
 echo
 firewall-cmd --reload
 echo
 echo -e "${YELLOW}[*] Firewall ports opened.${NC}"
 echo
}

#         Osquery Functions
# -------------------------------

# Downloads and Installs the Osquery on Debian based systems.
install_osquery_deb(){
 cd /tmp || exit
 echo
 echo -e "${PURPLE}[*] Downloading Osquery Agent.....${NC}"
 echo
 wget -O osquery_4.1.1_1.deb $OSQUERY_DEB_LOCATION
 echo
 echo -e "${PURPLE}[*] Osquery Agent Downloaded.${NC}"
 echo
 echo -e "${PURPLE}[*] Installing Osquery User Agent.....${NC}"
 echo
 sudo dpkg -i osquery_4.1.1_1.deb
 echo
 echo -e "${YELLOW}[*] Osquery Agent Installed.${NC}"
 echo
}

# Downloads and Installs the Osquery on Red Hat based systems.
install_osquery_rpm(){
 cd /tmp || exit
 echo
 echo -e "${PURPLE}[*] Downloading Osquery Agent.....${NC}"
 echo
 wget -O osquery_4.1.1_1.rpm $OSQUERY_RPM_LOCATION
 echo
 echo -e "${YELLOW}[*] Osquery Agent Downloaded.${NC}"
 echo
 echo -e "${PURPLE}[*] Installing Osquery User Agent.....${NC}"
 echo
 sudo rpm -i osquery_4.1.1_1.rpm
 echo
 echo -e "${YELLOW}[*] Osquery Agent Installed.${NC}"
 echo
}

#    Configuration Functions    
# -------------------------------

# This function will copy configuration files and packs from the defined
# /tmp directory to the appropriate osquery locations.
osquery_config(){

 cp "/tmp/CCDC-Setup/CCDC/osquery/1.Linux/osquery.conf" /etc/osquery/osquery.conf
 cp "/tmp/CCDC-Setup/CCDC/osquery/1.Linux/osquery.flags" /etc/osquery/osquery.flags
 cp -rf "/tmp/CCDC-Setup/CCDC/osquery/1.Linux/packs/" /etc/osquery/
 cp -rf "/tmp/CCDC-Setup/CCDC/osquery/1.Linux/packs/" /usr/share/osquery/

 osqueryctl config-check
 osqueryctl start --flagfile /etc/osquery/osquery.flags --disable_events=false
}

create_indexer_receivers(){
 echo
 echo -e "${GREEN}[*] Adding receiver to configuration files.....${NC}"
 echo
 echo "[splunktcp]" > /opt/splunk/etc/system/local/inputs.conf
 echo "[splunktcp://9997]" >> /opt/splunk/etc/system/local/inputs.conf
 echo "index = main" >> /opt/splunk/etc/system/local/inputs.conf
 echo "disabled = 0" >> /opt/splunk/etc/system/local/inputs.conf
 echo "" >> /opt/splunk/etc/system/local/inputs.conf
 echo
 echo -e "${YELLOW}[*] Enabled Splunk TCP input over 9997.${NC}"
 echo
 echo -e "${GREEN}[*] Adding receiver to configuration files.....${NC}"
 echo
 echo "[splunkudp]" > /opt/splunk/etc/system/local/inputs.conf
 echo "[splunkudp://514]" >> /opt/splunk/etc/system/local/inputs.conf
 echo "index = paloalto" >> /opt/splunk/etc/system/local/inputs.conf
 echo "disabled = 0" >> /opt/splunk/etc/system/local/inputs.conf
 echo "" >> /opt/splunk/etc/system/local/inputs.conf
 echo
 echo -e "${YELLOW}[*] Enabled Splunk UDP input over 514.${NC}"
 echo
}

edit_indexer_inputs(){
 echo -e "${GREEN}[*] Editing Splunk's input file....${NC}"
 echo 
 cd /opt/splunk/etc/system/local || exit

 echo -e "[monitor:///var/log/osquery/osqueryd.results.log]\nindex = osquery\nsourcetype = osquery:results\n\n" >> inputs.conf
 echo -e "[monitor:///var/log/osquery/osqueryd.*ERROR*]\nindex = osquery\nsourcetype = osquery:error\n\n" >> inputs.conf
 echo -e "[monitor:///var/log/osquery/osqueryd.*WARNING*]\nindex = osquery\nsourcetype = osquery:warning\n\n" >> inputs.conf
 echo -e "[monitor:///var/log/osquery/osqueryd.snapshot.log\nindex = osquery\nsourcetype = osquery:snapshots\n\n" >> inputs.conf

 echo -e "${YELLOW}[*] Complete.${NC}"
 echo
 echo -e "${GREEN}[*] Adding directories to monitor...${NC}"
 echo
 cd /opt/splunk/bin/ || exit

 # sudo ./splunk add monitor /var/log
 sudo ./splunk add monitor /etc/passwd
 echo
 echo -e "${YELLOW}[*] Complete.${NC}"
 echo
 echo -e "${GREEN}[*] Adding indexes...${NC}"
 echo
 sudo ./splunk add index osquery
 sudo ./splunk add index threathunting
 sudo ./splunk add index windows
 sudo ./splunk add index bro
 sudo ./splunk add index paloalto
 echo
 echo -e "${YELLOW}[*] Complete.${NC}"
 echo
 echo -e "${GREEN}[*] Restarting Splunk...${NC}"
 echo
 sudo ./splunk restart | tee -a 'install.file'
 sleep 5
 echo
 echo -e "${YELLOW}[*] Complete.${NC}"
 echo
}

# This will edit the local inputs.conf file on the Splunk Forwarder and
# add the indexer IP Address to the splunk forwarder configuration.
# User's will need to provide the IP Address of the Indexer when prompted.
edit_forwarder_inputs(){
 read -p "What is the IP Address of the Splunk Indexer? " indexerip
 echo
 echo -e "${GREEN}[*] Editing Splunk's input file...${NC}"
 echo
 cd /opt/splunkforwarder/etc/system/local || exit

 echo -e "[monitor:///var/log/osquery/osqueryd.results.log]\nindex = osquery\nsourcetype = osquery:results\n\n" >> inputs.conf
 echo -e "[monitor:///var/log/osquery/osqueryd.*ERROR*]\nindex = osquery\nsourcetype = osquery:error\n\n" >> inputs.conf
 echo -e "[monitor:///var/log/osquery/osqueryd.*WARNING*]\nindex = osquery\nsourcetype = osquery:warning\n\n" >> inputs.conf
 echo -e "[monitor:///var/log/osquery/osqueryd.snapshot.log\nindex = osquery\nsourcetype = osquery:snapshots\n\n" >> inputs.conf

 echo -e "${YELLOW}[*] Complete.${NC}"
 echo
 echo -e "${GREEN}[*] Adding directories to monitor...${NC}"
 echo
 cd /opt/splunkforwarder/bin/ || exit

 sudo ./splunk add monitor /var/log
 sudo ./splunk add monitor /etc/passwd
 echo
 echo -e "${YELLOW}[*] Complete.${NC}"
 echo
 echo -e "${GREEN}[*] Adding forward-server...${NC}"
 echo
 sudo ./splunk add forward-server "$indexerip":9997
 echo
 echo -e "${YELLOW}[*] Complete.${NC}"
 echo
 echo -e "${GREEN}[*] Restarting Splunk...${NC}"
 echo
 sudo ./splunk restart | tee -a 'install.file'
 if [ "$?" -eq "0" ]
 then
    echo -e "${YELLOW}[*] Complete.${NC}"
 else
    echo -e "${RED}[!] Splunk restart not successful.${NC}"
 fi
 echo
}


# Main body of script starts here
#
#
# Check for user arguments, if none provided, exit script.
if [ $# -eq 0 ];
then
    echo 
    echo -e "${RED}No arguments provided${NC}"
    exit 1
fi

while [ $# -ne 0 ]
do
    arg="$1"
    case "$arg" in
        --[uU]buntu)
            ubuntu=true
            ;;
        --[cC]entos)
            centos=true
            ;;
        --deps)
            deps=true
            ;;
        --help)
            help=true
            ;;
        --indexer)
            indexer=true
            ;;
        --forwarder)
            forwarder=true
            ;;
        --osquery)
            osquery=true
            ;;
        --check_forwarder)
            check_forwarder=true
            ;;
        --check_indexer)
            check_indexer=true
            ;;
        --ssl_indexer)
            ssl_indexer=true
            ;;
    esac
    shift
done

if [ "$help" = "true" ];
then
    echo
    echo -e "${GREEN}Usage:"
    echo "sudo ./CCDC_Installer [options]"
    echo "sudo ./CCDC_Installer [operating_system][os_option]${NC}"
    echo
    echo "The purpose of this program is to configure your toolset and install"
    echo "the necessary software.  The script accepts one operating system argument,"
    echo "and one install argument."
    echo
    echo "Options:"  
    echo "   --ssl_indexer            Enables ssl encryption on Splunk Web (Indexer Only)"
    echo "   --check_indexer          Checks to see if Splunk Enterprise is Installed"
    echo "   --check_forwarder        Checks to see if splunk binary is present on the system"
    echo "   --help                      Displays this help message"
    echo
    echo "Operating_system:"
    echo "   --ubuntu                 Determines which files to run based on"
    echo "   --centos                 operating system type. Needs to be argument 2"
    echo
    echo "Os_option:"
    echo "   --indexer                Dictates whether or not we need an indexer"
    echo "   --forwarder              or forwarder to be installed on the system"
    echo
    echo "   --osquery                Installs and configures Osquery endpoint agent"
    echo
    echo 
    echo "It is very important that the argument order be followed."
    echo -e "${GREEN}Examples:"
    echo "sudo ./CCDC_Installer --help"
    echo "sudo ./CCDC_Installer --check_indexer"
    echo -e "sudo ./CCDC_Installer --ubuntu --indexer${NC}"
    echo -e "sudo ./CCDC_Installer --centos --osquery${NC}"  
    echo "==========================================================================================="
fi
if [ "$check_forwarder" = "true" ];
        then
        splunk_forwarder_check
fi
if [ "$check_indexer" = "true" ];
        then
        splunk_indexer_check
fi
if [ "$ssl_indexer" = "true" ];
then
        enable_ssl_indexer
fi
if  [ "$ubuntu" = "true" ];
then
    if [ "$deps" =  "true" ];
    then
        dependency_install_deb
        if [ "$?" -eq "0" ];
        then
            sleep 5
            echo
            echo -e "${YELLOW}[*] Update Complete.${NC}"
        else
            sleep 5
            echo
            echo -e "${RED}[!] Update not successful.${NC}"

        fi
    elif [ "$indexer" = 'true' ];
    then
    #If --indexer is an argument, then it will install the indexer based on the system
        disable_hugh_pages_indexer
        sleep 1
        increase_ulimit_indexer
        sleep 1
        install_splunk_indexer
        sleep 1
        add_splunk_user_indexer
        sleep 1
        initial_run_indexer
        sleep 1
        indexer_firewall_rules_deb
        sleep 1
        create_indexer_receivers
        sleep 1
        edit_indexer_inputs
        if [ "$?" -eq "0" ];
        then
            sleep 5
            echo -e "${YELLOW}[*] Input Update Complete.${NC}"
        else
            sleep 5
            echo -e "${RED}[!] Inputs update not successful.${NC}"
        fi
    elif [ "$forwarder" = "true" ];
    then
            install_splunk_forwarder
            sleep 2
            add_splunk_user_forwarder
            sleep 2
            initial_run_forwarder
            sleep 2
            edit_forwarder_inputs
            if [ "$?" -eq "0" ];
        then
            sleep 5
            echo -e "${YELLOW}[*] Input Update Complete.${NC}"
        else
            sleep 5
            echo -e "${RED}[!] Inputs update not successful.${NC}"
        fi
    elif [ "$osquery" = "true" ];
    then
        install_osquery_deb
        sleep 1
        osquery_config
        if [ "$?" -eq "0" ];
        then
            sleep 5
            echo -e "${YELLOW}[*] Osquery Install Complete.${NC}"
        else
            sleep 5
            echo -e "${RED}[!] Osquery Install not successful.${NC}"
        fi
    fi
elif  [ "$centos" = "true" ];
then
    if [ "$deps" =  "true" ];
    then
        dependency_install_rpm
        if [ "$?" -eq "0" ];
        then
            sleep 5
            echo
            echo -e "${YELLOW}[*] Update Complete.${NC}"
        else
            sleep 5
            echo
            echo -e "${RED}[!] Update not successful.${NC}"

        fi
    elif [ "$indexer" = 'true' ];
    then
    #If --indexer is an argument, then it will install the indexer based on the system
        disable_hugh_pages_indexer
        sleep 1
        increase_ulimit_indexer
        sleep 1
        install_splunk_indexer
        sleep 1
        add_splunk_user_indexer
        sleep 1
        initial_run_indexer
        sleep 1
        indexer_firewall_rules_rpm
        sleep 1
        create_indexer_receivers
        sleep 1
        edit_indexer_inputs
        if [ "$?" -eq "0" ];
        then
            sleep 5
            echo -e "${YELLOW}[*] Input Update Complete.${NC}"
        else
            sleep 5
            echo -e "${RED}[!] Inputs update not successful.${NC}"
        fi
    elif [ "$forwarder" = "true" ];
    then
            install_splunk_forwarder
            sleep 2
            add_splunk_user_forwarder
            sleep 2
            initial_run_forwarder
            sleep 2
            edit_forwarder_inputs
            if [ "$?" -eq "0" ];
        then
            sleep 5
            echo -e "${YELLOW}[*] Input Update Complete.${NC}"
        else
            sleep 5
            echo -e "${RED}[!] Inputs update not successful.${NC}"
        fi
    elif [ "$osquery" = "true" ];
    then
        install_osquery_rpm
        sleep 1
        osquery_config
        if [ "$?" -eq "0" ];
        then
            sleep 5
            echo -e "${YELLOW}[*] Osquery Install Complete.${NC}"
        else
            sleep 5
            echo -e "${RED}[!] Osquery Install not successful.${NC}"
        fi
    fi
fi
# Exit with an explicit status code
exit 0



# TO-DO
#----------------------------------------
# Functions to add:
#
# deployment_apps (Adds apps to indexer)
# OpenVas_install
# input reminder (Print reminder for special inputs like bro) Maybe make premade inputs.conf.
# Fail2ban_install