# !/bin/bash


# Bash SOC Install script for CCDC Team Ubuntu Environments
# Version 3.0.1
# Written by Daniel Barr
#
# ---------------------------------------------------------------------
# Free to use by all teams. Please realize you are using this script
# at your own risk. The author holds no liability and will not be held
# responsible for any damages done to systems or system configurations.
# ---------------------------------------------------------------------
# This script should be used on any Linux system for installing TheHive Project
# elements: TheHive & Cortex.  This installs both systems on one server.
# For a distributed environment you may want to comment out the necessary functions
# and run the script on multiple systems. 
# ---------------------------------------------------------------------
# The goal of this script is to efficiently spin up a Incident Response system
# anaylts can use to track observables and report actions taken. Ideally this 
# setup will evolve to compliment SIEM event platform analysis.


# -------------------------------
# -      Global  Variables      -
# -------------------------------

CRYPTOKEY=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 64 | head -n1)

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
PURPLE='\033[0;35m'
BLUE='\033[0;36m'
NC='\033[0m'

# -------------------------------
# -          Functions          -
# -------------------------------


check_root(){
if [[ "$EUID" -ne 0 ]]; then
    echo
    echo "[!] This installer must be run as root."
    echo "[!] Please use sudo or switch to the root user"
    echo
    return 0
fi
}

check_previous(){
if [[ $? -eq 0 ]]; then
return 0
else
exit
fi
}

install_deps(){
    sudo apt-get install -y --no-install-recommends python-pip python2.7-dev python3-pip python3-dev ssdeep libfuzzy-dev libfuzzy2 libimage-exiftool-perl libmagic1 build-essential git libssl-dev apt install apt-transport-https
    check_previous
    sudo pip install -U pip setuptools && sudo pip3 install -U pip setuptools
    check_previous
}

install_thehiveproject(){
    echo 'deb https://dl.bintray.com/thehive-project/debian-stable any main' | tee -a /etc/apt/sources.list.d/thehive-project.list
    check_previous
    sleep 1
    curl https://raw.githubusercontent.com/TheHive-Project/TheHive/master/PGP-PUBLIC-KEY | sudo apt-key add -
    check_previous
    sleep 1
    check_previous
    sleep 1
    apt-get update -y
    check_previous
    sleep 1
    apt-get install thehive cortex -y
    check_previous
}

install_elastic(){
    apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-key D88E42B4
    check_previous
    echo "deb https://artifacts.elastic.co/packages/5.x/apt stable main" | tee -a /etc/apt/sources.list.d/elastic-5.x.list
    check_previous
    apt update -y && sudo apt install elasticsearch -y
    check_previous
}


configure_elastic(){
(cat << _EOF_
network.host: 127.0.0.1
script.inline: true
cluster.name: hive
thread_pool.index.queue_size: 100000
thread_pool.search.queue_size: 100000
thread_pool.bulk.queue_size: 100000
_EOF_
) | sudo tee -a /etc/elasticsearch/elasticsearch.yml
check_previous
}

secure_thehiveproject(){
(cat << _EOF_
play.modules.enabled += connectors.cortex.CortexConnector

# Secret key
# ~~~~~
# The secret key is used to secure cryptographics functions.
# If you deploy your application to several instances be sure to use the same key!
play.http.secret.key="$CRYPTOKEY"
_EOF_
) | sudo tee -a /etc/thehive/application.conf
check_previous
}

download_cortexdeps(){
    git clone https://github.com/TheHive-Project/Cortex-Analyzers /opt/cortex/Cortex-Analyzers
    cd /opt/cortex/Cortex-Analyzers
    for I in $(find Cortex-Analyzers -name 'requirements.txt'); do sudo -H pip2 install -r $I; done && \
    for I in $(find Cortex-Analyzers -name 'requirements.txt'); do sudo -H pip3 install -r $I || true; done
    sleep 3
    check_previous
}

configure_cortex(){
(cat << _EOF_
analyzer {
  # Directory that holds analyzers
  path = [
    "/opt/cortex/Cortex-Analyzers/analyzers"
  ]

  fork-join-executor {
    # Min number of threads available for analyze
    parallelism-min = 2
    # Parallelism (threads) ... ceil(available processors * factor)
    parallelism-factor = 2.0
    # Max number of threads available for analyze
    parallelism-max = 4
  }
}

responder {
  # Directory that holds responders
  path = [
    "/opt/cortex/Cortex-Analyzers/responders"
  ]

  fork-join-executor {
    # Min number of threads available for analyze
    parallelism-min = 2
    # Parallelism (threads) ... ceil(available processors * factor)
    parallelism-factor = 2.0
    # Max number of threads available for analyze
    parallelism-max = 4
  }
}
_EOF_
) | tee -a /etc/cortex/application.conf
check_previous
(cat << _EOF_
# Secret key
# ~~~~~
# The secret key is used to secure cryptographics functions.
# If you deploy your application to several instances be sure to use the same key!
play.http.secret.key="$CRYPTOKEY"
_EOF_
) | sudo tee -a /etc/cortex/application.conf
check_previous
}

enable_services(){
    systemctl enable elasticsearch.service
    check_previous
    systemctl enable thehive.service
    check_previous
    systemctl enable cortex.service
    check_previous
}

start_services(){
    systemctl start elasticsearch.service
    check_previous
    systemctl start thehive.service
    check_previous
    systemctl start cortex.service
    check_previous
}

# -------------------------------
# -        Script Start         -
# -------------------------------

check_root
apt update -y && apt upgrade -y
sleep 3
echo
echo -e "${GREEN}[*] Installing TheHive & Cortex...${NC}"
echo
install_thehiveproject
echo
echo -e "${GREEN}[*] Complete${NC}"
echo
sleep 3
echo
echo -e "${GREEN}[*] Installing Elastisearch 5...${NC}"
echo
install_elastic
echo
echo -e "${GREEN}[*] Complete${NC}"
echo
sleep 3
echo
echo -e "${GREEN}[*] Configuring Elastisearch 5...${NC}"
echo
configure_elastic
echo
echo -e "${GREEN}[*] Complete${NC}"
echo
sleep 3
echo
echo -e "${GREEN}[*] Adding TheHive & Cortex security key...${NC}"
echo
secure_thehiveproject
echo
echo -e "${GREEN}[*] Complete${NC}"
echo
sleep 3
echo
echo -e "${GREEN}[*] Downloading Cortex Analyzers & Responders...${NC}"
echo
download_cortexdeps
echo
echo -e "${GREEN}[*] Complete${NC}"
echo
sleep 3
echo
echo -e "${GREEN}[*] Installing Cortex Analyzers & Responders Dependencies...${NC}"
echo
configure_cortex
echo
echo -e "${GREEN}[*] Complete${NC}"
echo
sleep 3
echo
echo -e "${GREEN}[*] Enabling Services...${NC}"
echo
enable_services
echo
echo -e "${GREEN}[*] Complete${NC}"
echo
sleep 3
echo
echo -e "${GREEN}[*] Starting TheHive, Cortex, & Elasicsearch...${NC}"
echo
start_services
echo
echo -e "${GREEN}[*] Complete${NC}"
echo

# Exit with an explicit status code
exit 0
