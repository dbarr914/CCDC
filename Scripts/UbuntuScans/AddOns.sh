#!/bin/bash
# Bash Install script for Pace CCDC Team Linux Environment
# Version 1.0.8
# Written by Daniel Barr

deployment_apps(){
 read -p "What is the home folder where the git repo is stored? " userhome
 echo
 echo "[*] Installing Add-ons..."
 echo
 cd /home/$userhome/CCDC/Splunk/Add-Ons/
 cp ./* /opt/splunk/etc/deployment-apps/
 echo
 cd /opt/splunk/etc/deployment-apps
 echo
 #Sysmon TA
 unzip TA-microsoft-sysmon-master.zip
 cp -rf TA-microsoft-sysmon-master /opt/splunk/etc/apps/
 rm TA-microsoft-sysmon-master.zip

 #Osquery TA
 unzip TA-osquery-master.zip
 cp -rf TA-osquery-master /opt/splunk/etc/apps
 rm TA-osquery-master.zip

 #Force Direct App
 tar -xvf force-directed-app-for-splunk_301.tgz
 cp -rf force_directed_viz /opt/splunk/etc/apps
 rm force-directed-app-for-splunk_301.tgz

 #Link Analysis App
 tar -xvf link-analysis-app-for-splunk_161.tgz
 cp -rf link_analysis_app /opt/splunk/etc/apps
 rm link-analysis-app-for-splunk_161.tgz

 #Punchcard App
 tar -xvf punchcard-custom-visualization_140.tgz
 cp -rf punchcard_app /opt/splunk/etc/apps
 rm punchcard-custom-visualization_140.tgz

 #Sankey App
 tar -xvf sankey-diagram-custom-visualization_140.tgz
 cp -rf sankey_diagram_app /opt/splunk/etc/apps
 rm sankey-diagram-custom-visualization_140.tgz

 #Microsoft App
 tar -xvf splunk-add-on-for-microsoft-windows_700.tgz
 cp -rf Splunk_TA_windows /opt/splunk/etc/apps
 rm splunk-add-on-for-microsoft-windows_700.tgz

 #Nginx App
 tar -xvf splunk-add-on-for-nginx_100.tgz
 cp -rf Splunk_TA_nginx /opt/splunk/etc/apps
 rm splunk-add-on-for-nginx_100.tgz

 #Zeek App
 tar -xvf splunk-add-on-for-zeek-aka-bro_400.tgz
 cp -rf Splunk_TA_bro /opt/splunk/etc/apps
 rm splunk-add-on-for-zeek-aka-bro_400.tgz

 #CIM App
 tar -xvf splunk-common-information-model-cim_4140.tgz
 cp -rf Splunk_SA_CIM /opt/splunk/etc/apps
 rm splunk-common-information-model-cim_4140.tgz

 #Threat Hunting App
 tar -xvf threathunting_141.tgz
 cp -rf ThreatHunting /opt/splunk/etc/apps
 rm threathunting_141.tgz

 #Timeline App
 tar -xvf timeline-custom-visualization_140.tgz
 cp -rf timeline_app /opt/splunk/etc/apps
 rm timeline-custom-visualization_140.tgz

 echo "[*] Complete."
 echo
}

lookup_tables(){
   read -p "What is the splunk admin username? " splunkadmin
   echo
   echo "[*] Copying Lookup tables to appropriate directories..."
   echo
   cp -rf /home/$userhome/CCDC/Splunk/lookups/ /opt/splunk/etc/users/$splunkadmin/ThreatHunting/
   echo "[*] Complete."
   echo
 }
 
 restart_splunk(){
   echo "[*] Restarting Splunk..."
   echo
   cd /opt/splunk/bin
   ./splunk restart
   echo "[*] Complete."
   echo
 }
   
 
 deployment_apps
 lookup_tables
 restart_splunk
