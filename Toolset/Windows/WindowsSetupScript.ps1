#
# Powershell install script for Pace CCDC Team Windows Environment
# Version 1.0.0
# Written by Daniel Barr
# 
# ---------------------------------------------------------------------
# Free to use by all teams. Please realize you are using this script
# at your own risk. The author holds no liability and will not be held
# responsible for any damages done to systems or system configurations.
# ---------------------------------------------------------------------
# This script will install the CHOCOLATEY package management system, 
# OSQUERY 4.0.2 endpoint visibility agent, SYSMON event driver and
# SPLUNK UNIVERSAL FORWARDER. In addition it will download the 
# predetermined configuration files.
# ---------------------------------------------------------------------
# Take note these configurations may need to be adjusted by the user as
# needed. Every environment is different and should be treated as such.
# ---------------------------------------------------------------------
# The goal of this install script is to efficiently deploy the necessary
# tool-sets for effective system monitoring during the Collegiate Cyber
# Defense Competition. This tool-set represents a larger overall strategy
# and should be tailored to your specific team.
#
#
#                             CHOCOLATEY/GIT INSTALL
# ---------------------------------------------------------------------
# Set the powershell execution policy to 'Bypass'.
# Then download the chocolatey package manager from their website.
#
Write-Host '* Installing the chocolatey package manager...' -ForegroundColor Magenta
Set-ExecutionPolicy Bypass -Scope Process -Force; 
Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
#
# Download github repository containing Windows configuration files.
#
Write-Host '* Downloading the necessary configuration files...' -ForegroundColor Magenta
git clone https://github.com/dbarr914/CCDC.git ~\
#
#                             OSQUERY INSTALL
# ---------------------------------------------------------------------
# Install OSQUERYD DAEMON as a Windows SYSTEM level service.
#
Write-Host '* Installing the osquery daemon as a Windows Service...' -ForegroundColor Magenta
choco install osquery -params '"/InstallService"'
#
#
# Copy OSQUERY PACKS into the 'C:\Program Files\osquery\packs' directory.
#
Copy-Item -path '~\CCDC\osquery\packs\*' -Destination 'C:\Program Files\osquery\packs\*' -Force
#
#Copy OSQUERY Configuration File into the 'C:\Program Files\osquery\' directory.
#
Copy-Item -path '~\CCDC\osquery\osquery.conf' -Destination 'C:\Program Files\osquery\' -Force
#
# Restart the OSQUERY service.
#
'C:\Program Files\osquery\manage-osqueryd.ps1' stop
'C:\Program Files\osquery\manage-osqueryd.ps1' start
#
# 
# Check to see if the OSQUERY service is running. If it is continue to the next step, if not, error out.
#
$osqServiceName = 'osqueryd' # Provide service name in variable.

$osqService = Get-Service -Name $osqServiceName # Store the command.

Write-Host '* Getting OSQUERY Status...' -ForegroundColor Magenta # Display what is happening to the user.

Start-Sleep -seconds 5 # Take a second or five to relax.

# Define check status function.
function Get-OsqueryStatus {
# Check if the status of the service is equal to 'Running'.
  if ($osqService.Status -eq 'Running'){
	Write-Host '* Service is Running' -ForegroundColor Green
	Return # If the service is running break out of the function and continue.
	} else { 
	# Tell the user there was a problem and offer some troubleshooting guidance.
	Write-Host '* Service is Not Running!' -ForegroundColor Red
	Write-Host '* Check your configuration files, directory & file permissions, etc.' -ForegroundColor Yellow
	Write-Host '* Then re-run the script.' -ForegroundColor Yellow
	exit # If the service is not running terminate the script.
	}
}

# Call the function to check the status of the OSQUERYD daemon.
Check-Osquery-Status


#                         SYSMON INSTALL
# ---------------------------------------------------------------------
#
Write-Host '* ' -ForegroundColor Magenta
Write-Host '* ' -ForegroundColor Magenta
Write-Host '* ' -ForegroundColor Magenta
#
# Install SYSMON DRIVER as a Windows Service.
#
Set-Location '~\CCDC\sysmon\'
Write-Host '* Installing the sysmon driver...' -ForegroundColor Magenta
.\Sysmon64.exe -i .\z-AlphaVersion.xml -h sha1,imphash -n               # Important Note! The configuration file should.
#
#
# Check to see if the SYSMON service is running. If it is continue to the next step, if not, error out.
#
$sysServiceName = 'Sysmon64' # Provide service name in variable.

$sysService = Get-Service -Name $sysServiceName # Store the command.

Write-Host '* Getting SYSMON Status...' -ForegroundColor Magenta # Display what is happening to the user.

Start-Sleep -seconds 5 # Take a second or five to relax.

# Define check status function.
function Get-SysmonStatus {
# Check if the status of the service is equal to 'Running'.
  if ($sysService.Status -eq 'Running'){
	Write-Host '* Sysmon Service is Running' -ForegroundColor Green
	Return # If the service is running break out of the function and continue.
	} else { 
	# Tell the user there was a problem and offer some troubleshooting guidance.
	Write-Host '[!] Service is Not Running!' -ForegroundColor Red
	Write-Host '[!] Check your configuration files, directory & file permissions, etc.' -ForegroundColor Yellow
	Write-Host '[!] Then re-run the script.' -ForegroundColor Yellow
	exit # If the service is not running terminate the script.
	}
}

# Call the function to check the status of the OSQUERYD daemon.
Check-Sysmon-Status

#                   SPLUNK UNIVERSAL FORWARDER INSTALL
# ---------------------------------------------------------------------
#
Write-Host '* ' -ForegroundColor Magenta
Write-Host '* ' -ForegroundColor Magenta
Write-Host '* ' -ForegroundColor Magenta

Write-Host '* Changing to Active Users home directory...'
Start-Sleep -seconds 1 # Take a second or five to relax.
Set-Location '~\'
# Download the SPLUNK UNIVERSAL FORWARDER from the splunk.com website.
Write-Host '* Downloading Splunk Universal Forwarder...' -ForegroundColor Magenta
Invoke-WebRequest -O splunkforwarder-8.msi 'https://www.splunk.com/bin/splunk/DownloadActivityServlet?architecture=x86_64&platform=windows&version=8.0.0&product=universalforwarder&filename=splunkforwarder-8.0.0-1357bef0a7f6-x64-release.msi&wget=true'

# Run the Splunk Forwarder Install Script.
Write-Host '* Installing Splunk Universal Forwarder...' -ForegroundColor Magenta
Start-Process -FilePath ~\CCDC\Scripts\WindowsScans\ForwarderInstallWindows.ps1 -Wait
Pause

