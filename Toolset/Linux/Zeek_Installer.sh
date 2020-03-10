#!/bin/bash
#
#
# This is nowhere near finished.  Goal is to have it working by the time I move to get my homelab setup.
#
#
# -------------------------------
# -      Global  Variables      -
# -------------------------------
ETHERNETADAPTER=$(ip link | awk -F: '$0 !~ "lo|vir|wl|^[^0-9]"{print $2;getline}' | awk '{$1=$1};1')
MAXRINGPARAM=$(sudo ethtool -g $ETHERNETADAPTER | awk -F: '{print $2;getline}' | awk '{$1=$1};1' | sort -nr  | awk 'NR==1{print $1}')

# -------------------------------
# -          Functions          -
# -------------------------------


# -------------------------------
# -        Script Start         -
# -------------------------------
 
# Create installer location in /tmp directory
mkdir /tmp/ZeekInstaller
cd /tmp/ZeekInstaller

cp ZeekInstaller.sh /tmp/ZeekInstaller


############################################################################
COPY TO SCRIPT CALLED ZEEKINSTALLER.sh



before_reboot(){
    # Install the network-scripts package. 
    sudo yum install network-scripts -y

    # Determine the maximum ring parameters for your sniffing interfaces.
    sudo ethtool -g $ETHERNETADAPTER

(cat << _EOF_
TYPE=Ethernet
BOOTPROTO=none
DEFROUTE=yes
IPV4_FAILURE_FATAL=no
IPV6INIT=no
IPV6_AUTOCONF=yes
IPV6_DEFROUTE=yes
IPV6_PEERDNS=yes
IPV6_PEERROUTES=yes
IPV6_FAILURE_FATAL=no
NAME=enp2s0
UUID=b22f5d92-3f1e-430b-b660-cb9376d8c0c0
DEVICE=enp2s0
ONBOOT=yes
PEERDNS=yes
PEERROUTES=yes
USERS=root
NM_CONTROLLED=no
ETHTOOL_OPTS="-G ${DEVICE} rx $MAXRINGPARAM; -K ${DEVICE} rx off; -K ${DEVICE} tx off; -K ${DEVICE} sg off; -K ${DEVICE} tso off; -K ${DEVICE} ufo off; -K ${DEVICE} gso off; -K ${DEVICE} gro off; -K ${DEVICE} lro off"
_EOF_
) | tee /etc/sysconfig/network-scripts/ifcfg-$ETHERNETADAPTER

    # Enable the “network” service
    sudo systemctl enable network

    # Restart the “network” service. 
    sudo systemctl restart network


    # Set sniffing network interfaces to promiscuous mode

(cat << _EOF_
[Unit]
Description=Makes an interface run in promiscuous mode at boot
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/ip link set dev $ETHERNETADAPTER promisc on
TimeoutStartSec=0
RemainAfterExit=yes

[Install]
WantedBy=default.target
_EOF_
) | tee /etc/systemd/system/promisc.service

    # Make the changes permanent and start on boot
    sudo chmod u+x /etc/systemd/system/promisc.service
    sudo systemctl start promisc.service
    sudo systemctl enable promisc.service

    # Create a file to test reboot condition
    touch /var/run/rebooting-for-updates
    sudo reboot
}

after_reboot(){
    # Install Zeek Dependencies

    # Enable Powertools Repository
    enable_Powertools(){
(cat << _EOF_
# CentOS-PowerTools.repo
#
# The mirror system uses the connecting IP address of the client and the
# update status of each mirror to pick mirrors that are updated to and
# geographically close to the client.  You should use this for CentOS updates
# unless you are manually picking other mirrors.
#
# If the mirrorlist= does not work for you, as a fall back you can try the
# remarked out baseurl= line instead.
#
#

[PowerTools]
name=CentOS-$releasever - PowerTools
mirrorlist=http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=PowerTools&infra=$infra
#baseurl=http://mirror.centos.org/$contentdir/$releasever/PowerTools/$basearch/os/
gpgcheck=1
enabled=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial
_EOF_
) | sudo tee /etc/yum.repos.d/CentOS-PowerTools.repo
    }

########################################################################################################################################################################
sudo yum install cmake make gcc gcc-c++ flex bison libpcap-devel openssl-devel platform-python-devel swig zlib-devel kernel-devel kernel-headers -y

}

 
if [ -f /var/run/rebooting-for-updates ]; then
    after_reboot
    rm /var/run/rebooting-for-updates
    update-rc.d myupdate remove
else
    before_reboot
    touch /var/run/rebooting-for-updates
    update-rc.d myupdate defaults
    sudo reboot
fi


check_promisc(){
    PROMISC=$(ip a show $ETHERNETADAPTER | grep -i promisc | awk -F, '{print $3}' )
    if [[ $PROMISC = "PROMISC"]];
    then
    return 0
    else
    echo "The current ethernet adapter is not in PROMISC mode"
    echo "Please check for errors and rerun."
    exit
    fi
}

# Exit with an explicit status code
exit 0
(cat << _EOF_
# CentOS-PowerTools.repo
#
# The mirror system uses the connecting IP address of the client and the
# update status of each mirror to pick mirrors that are updated to and
# geographically close to the client.  You should use this for CentOS updates
# unless you are manually picking other mirrors.
#
# If the mirrorlist= does not work for you, as a fall back you can try the
# remarked out baseurl= line instead.
#
#

[PowerTools]
name=CentOS-$releasever - PowerTools
mirrorlist=http://mirrorlist.centos.org/?release=$releasever&arch=$basearch&repo=PowerTools&infra=$infra
#baseurl=http://mirror.centos.org/$contentdir/$releasever/PowerTools/$basearch/os/
gpgcheck=1
enabled=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-centosofficial
_EOF_
 ) | sudo tee /etc/yum.repos.d/CentOS-PowerTools.repo
