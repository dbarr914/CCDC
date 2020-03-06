function Invoke-WindowsScan {
<#
.SYNOPSIS
    Overview:
    
    Powershell Inventory & IR script for CCDC Team Windows Environments.
    
    Parameters:
     -ScanType          Specifiy the type of scan you would like to run. A brief inventory scan or full incident scan.
        Options:        Inventory
                        Incident

     -DestinationEmail  Specify the email you would like to send the report to.
     
     -SourceEmail       Specify the email you would like to send the report from.
    
                       
.DESCRIPTION
	Author: Daniel Barr 
	Required Dependencies: None
    Optional Dependencies: None
    
    DISCLOSURE:
    # Free to use by all teams. Please realize you are using this script
    # at your own risk. The author holds no liability and will not be held
    # responsible for any damages done to systems or system configurations.
    # ---------------------------------------------------------------------
    # Take note these configurations may need to be adjusted by the user as
    # needed. Every environment is different and should be treated as such.
    # ---------------------------------------------------------------------
    # The goal of this to efficiently triage the necessary areas of a possibly
    # compromised system during the Collegiate Cyber Defense Competition.
    # This tool-set represents a larger overall strategy and should be tailored
    #  to your specific team strategy.

.EXAMPLE
	Run an inventory scan without sending it anywhere. File will exist locally on the system.
	C:\PS> Invoke-WindowsScan -ScanType Inventory	
.EXAMPLE
	Run an inventory scan and send it to <destination@email.com> from <source@email.com>. 
    C:\PS> Invoke-WindowsScan -ScanType Inventory -DestinationEmail <destination@email.com> -SourceEmail <source@email.com>
.EXAMPLE
	Run an incident scan and send it to <destination@email.com> from <source@email.com>. 
    C:\PS> Invoke-WindowsScan -ScanType Incident -DestinationEmail <destination@email.com> -SourceEmail <source@email.com>
    
#>
    param(
        [Parameter(Mandatory=$true)]
        [string] $ScanType,
        [string] $DestinationEmail,
        [string] $SourceEmail)
#
#
##################################################################################################################################
#                            GLOBAL VARIABLES
# ---------------------------------------------------------------------

$global:extensions="*.cmd","*.bat","*.vbs","*.js","*.com","*.exe","*.wsf","*.swf","*.jar","*.dat"
$global:date=(Get-Date -Format "MM-dd-yyy-h-m-s")
$global:LocalDirectory=Get-Location
$global:ReportDirectory="$global:LocalDirectory\$env:COMPUTERNAME-IncidentReports-$global:date"
$global:FinalReportDirectory="$global:ReportDirectory\$env:COMPUTERNAME-FinalIncidentReport"
##################################################################################################################################
#                           REPORTING FUNCTIONS
# ---------------------------------------------------------------------
# Send report over email using google smtp
function Send-IncidentReport([string]$srcemail,[string]$dstemail){
    $From = $srcemail
    $To = $dstemail
    $Subject = "$env:computername Incident Report"
    $Attachment = "$global:FinalReportDirectory\$env:computername-SystemIncidentReport-$global:date.txt"
    $Body = "<h2>See attached the following incident response report for $env:computername.</h2><br>"
    $Body += "<p>It contains pertinent information associated to the named computer.</p><br>"
    $Body += "<p>Please investigate the data further.</p>"
    $SMTPServer = "smtp.gmail.com"
    $SMTPPort = "587"
    Send-MailMessage -From $From -to $To -Subject $Subject -Body $Body -BodyAsHtml -SmtpServer $SMTPServer -Port $SMTPPort -UseSsl -Credential (Get-Credential) -Attachments $Attachment
}

function Send-InventoryReport([string]$srcemail,[string]$dstemail){
    $From = $srcemail
    $To = $dstemail
    $Subject = "$env:computername Inventory Report"
    $Attachment = "$global:FinalReportDirectory\$env:computername-SystemInventoryReport-$global:date.txt"
    $Body = "<h2>See attached the following inventory report for $env:computername.</h2><br>"
    $Body += "<p>It contains pertinent information associated to the named computer.</p>"
    $SMTPServer = "smtp.gmail.com"
    $SMTPPort = "587"
    Send-MailMessage -From $From -to $To -Subject $Subject -Body $Body -BodyAsHtml -SmtpServer $SMTPServer -Port $SMTPPort -UseSsl -Credential (Get-Credential) -Attachments $Attachment
}

function Set-ColorGreen
{
    process { Write-Host $_ -ForegroundColor Green }
}
function Set-ColorRed
{
    process { Write-Host $_ -ForegroundColor Red }
}
function Set-ColorMagenta
{
    process { Write-Host $_ -ForegroundColor Magenta }
}
function Set-ColorWhite
{
    process { Write-Host $_ -ForegroundColor White }
}
function Set-ColorBlue
{
    process { Write-Host $_ -ForegroundColor Cyan }
}
#
##################################################################################################################################
#                       BASIC INFO FUNCTIONS
# ---------------------------------------------------------------------
# Get Generic Overview of system information
function Get-SystemInfo {
    Write-Output '------------------------------------------------------------' | Tee-Object -File "$Env:COMPUTERNAME-SystemInfo.txt" -Append | Set-ColorGreen
    Write-Output '                       SYSTEM REPORT ' | Tee-Object -File "$Env:COMPUTERNAME-SystemInfo.txt" -Append | Set-ColorGreen
    Write-Output '------------------------------------------------------------' | Tee-Object -File "$Env:COMPUTERNAME-SystemInfo.txt" -Append | Set-ColorGreen
    Write-Output '' | Tee-Object -File "$Env:COMPUTERNAME-SystemInfo.txt" -Append | Set-ColorWhite
    Write-Output "Start-Time: $global:date" | Tee-Object -File "$Env:COMPUTERNAME-SystemInfo.txt" -Append | Set-ColorWhite
    Write-Output '' | Tee-Object -File "$Env:COMPUTERNAME-SystemInfo.txt" -Append | Set-ColorWhite
    Write-Output '-----------------------' | Tee-Object -File "$Env:COMPUTERNAME-SystemInfo.txt" -Append | Set-ColorGreen
    Write-Output '[*] Basic System Info ' | Tee-Object -File "$Env:COMPUTERNAME-SystemInfo.txt" -Append | Set-ColorGreen
    Write-Output '-----------------------' | Tee-Object -File "$Env:COMPUTERNAME-SystemInfo.txt" -Append | Set-ColorGreen
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-SystemInfo.txt" -Append | Set-ColorWhite
    systeminfo | Tee-Object -File "$Env:COMPUTERNAME-SystemInfo.txt" -Append | Set-ColorWhite
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-SystemInfo.txt" -Append | Set-ColorWhite
}

##################################################################################################################################
#                   INCIDENT RESPONSE SPECIFIC FUNCTIONS
# ---------------------------------------------------------------------
# Compute MD5 and SHA256 hashes of executable files in %WINDIR%\System32, 
# %SystemDrive%\Temp\, and all files in %TEMP%
#
function Get-MD5Hash {
    Write-Output '-----------------------' | Tee-Object -File "$Env:COMPUTERNAME-MD5SystemHashes.txt" -Append | Set-ColorGreen
    Write-Output '[*]  MD5 hash values' | Tee-Object -File "$Env:COMPUTERNAME-MD5SystemHashes.txt" -Append | Set-ColorGreen
    Write-Output '-----------------------'| Tee-Object -File "$Env:COMPUTERNAME-MD5SystemHashes.txt" -Append | Set-ColorGreen
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-MD5SystemHashes.txt" -Append | Set-ColorWhite
    Get-ChildItem $env:WINDIR\system32\* | Get-FileHash -Algorithm MD5 | Tee-Object -File "$Env:COMPUTERNAME-MD5SystemHashes.txt" -Append | Set-ColorWhite
    Get-ChildItem $env:SYSTEMROOT\Temp | Get-FileHash -Algorithm MD5 | Tee-Object -File "$Env:COMPUTERNAME-MD5SystemHashes.txt" -Append | Set-ColorWhite
    Get-ChildItem "$env:TEMP" | Get-FileHash -Algorithm MD5 | Tee-Object -File "$Env:COMPUTERNAME-MD5SystemHashes.txt" -Append | Set-ColorWhite
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-MD5SystemHashes.txt" -Append | Set-ColorWhite
}

function Get-SHA256Hash {
    Write-Output '-----------------------' | Tee-Object -File "$Env:COMPUTERNAME-SHA256SystemHashes.txt" -Append | Set-ColorGreen
    Write-Output '[*] SHA256 hash values' | Tee-Object -File "$Env:COMPUTERNAME-SHA256SystemHashes.txt" -Append | Set-ColorGreen
    Write-Output '-----------------------' | Tee-Object -File "$Env:COMPUTERNAME-SHA256SystemHashes.txt" -Append | Set-ColorGreen
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-SHA256SystemHashes.txt" -Append | Set-ColorWhite
    Get-ChildItem $env:WINDIR\system32\* | Get-FileHash -Algorithm SHA256 | Tee-Object -File "$Env:COMPUTERNAME-SHA256SystemHashes.txt" -Append | Set-ColorWhite
    Get-ChildItem $env:SYSTEMROOT\Temp | Get-FileHash -Algorithm SHA256 | Tee-Object -File "$Env:COMPUTERNAME-SHA256SystemHashes.txt" -Append | Set-ColorWhite
    Get-ChildItem "$env:TEMP" | Get-FileHash -Algorithm SHA256 | Tee-Object -File "$Env:COMPUTERNAME-SHA256SystemHashes.txt" -Append | Set-ColorWhite
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-SHA256SystemHashes.txt" -Append | Set-ColorWhite
}

function Get-SuspiciousFiles {
    Write-Output '--------------------------' | Tee-Object -File "$Env:COMPUTERNAME-SuspiciousFiles.txt" -Append | Set-ColorGreen
    Write-Output '[*] Suspicious Files    ' | Tee-Object -File "$Env:COMPUTERNAME-SuspiciousFiles.txt" -Append | Set-ColorGreen
    Write-Output '--------------------------' | Tee-Object -File "$Env:COMPUTERNAME-SuspiciousFiles.txt" -Append | Set-ColorGreen
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-SuspiciousFiles.txt" -Append | Set-ColorWhite
    Get-ChildItem -Recurse $env:SYSTEMDRIVE\Users -Include $global:extensions | Tee-Object -File "$Env:COMPUTERNAME-SuspiciousFiles.txt" -Append | Set-ColorWhite
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-SuspiciousFiles.txt" -Append | Set-ColorWhite
}

##################################################################################################################################
#                             USER FUNCTIONS
# ---------------------------------------------------------------------
# Get a list of users on the system.
function Get-Users {
        $LclUsers = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount='True'" | Select-Object Name, Status, Disabled, AccountType, PasswordRequired, PasswordChangeable, SID | Format-Table -AutoSize -Wrap
        $Groups = Get-LocalGroup
        $Results = foreach( $Group in $Groups ){
        $groupname = net localgroup $Group | 
        Where-Object {$_ -AND $_ -notmatch "command completed successfully"} | Select-Object -skip 4
    
        New-Object PSObject -Property @{
        Group = "$Group"
        Users= "$groupname"
        Computer_Name = "$env:COMPUTERNAME"
        }
      }

    Write-Output '-----------------------' | Tee-Object -File "$Env:COMPUTERNAME-UserReport.txt" -Append | Set-ColorGreen
    Write-Output '[*] User Accounts' | Tee-Object -File "$Env:COMPUTERNAME-UserReport.txt" -Append | Set-ColorGreen 
    Write-Output '-----------------------' | Tee-Object -File "$Env:COMPUTERNAME-UserReport.txt" -Append | Set-ColorGreen
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-UserReport.txt" -Append | Set-ColorWhite
    Write-Output '[*] Current User' | Tee-Object -File "$Env:COMPUTERNAME-UserReport.txt" -Append | Set-ColorMagenta
    Write-Output '-----------------------' | Tee-Object -File "$Env:COMPUTERNAME-UserReport.txt" -Append | Set-ColorMagenta
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-UserReport.txt" -Append | Set-ColorWhite
    whoami | Tee-Object -File "$Env:COMPUTERNAME-UserReport.txt" -Append
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-UserReport.txt" -Append | Set-ColorWhite 
    Write-Output 'Local Users' | Tee-Object -File "$Env:COMPUTERNAME-UserReport.txt" -Append | Set-ColorMagenta
    Write-Output '-----------------------' | Tee-Object -File "$Env:COMPUTERNAME-UserReport.txt" -Append | Set-ColorMagenta
    $LclUsers | Tee-Object -File "$Env:COMPUTERNAME-UserReport.txt" -Append
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-UserReport.txt" -Append | Set-ColorWhite
    Write-Output 'By Group' | Tee-Object -File "$Env:COMPUTERNAME-UserReport.txt" -Append | Set-ColorMagenta
    Write-Output '-----------------------' | Tee-Object -File "$Env:COMPUTERNAME-UserReport.txt" -Append | Set-ColorMagenta
    $Results | Tee-Object -File "$Env:COMPUTERNAME-UserReport.txt" -Append
}

function Get-UserDirectories {
    Write-Output '--------------------------' | Tee-Object -File "$Env:COMPUTERNAME-UserReport.txt" -Append | Set-ColorGreen
    Write-Output '[*] User Directories    '  | Tee-Object -File "$Env:COMPUTERNAME-UserReport.txt" -Append | Set-ColorGreen
    Write-Output '--------------------------' | Tee-Object -File "$Env:COMPUTERNAME-UserReport.txt" -Append | Set-ColorGreen
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-UserReport.txt" -Append | Set-ColorWhite
    Get-ChildItem -Directory $env:SYSTEMDRIVE\Users -Name | Tee-Object -File "$Env:COMPUTERNAME-UserReport.txt" -Append | Set-ColorWhite
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-UserReport.txt" -Append | Set-ColorWhite
}

#
##################################################################################################################################
#                  PROCESS INFORMATION FUNCTIONS
# ---------------------------------------------------------------------
# List all loaded dlls
#
function Get-LoadedDlls {
    Write-Output '[*] Loaded DLLs' | Tee-Object -File "$Env:COMPUTERNAME-LoadedDllsReport.txt" -Append | Set-ColorMagenta
    Write-Output '-----------------------' | Tee-Object -File "$Env:COMPUTERNAME-LoadedDllsReport.txt" -Append | Set-ColorMagenta
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-LoadedDllsReport.txt" -Append | Set-ColorWhite
    tasklist /M /FO List | Tee-Object -File "$Env:COMPUTERNAME-LoadedDllsReport.txt" -Append | Set-ColorWhite
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-LoadedDllsReport.txt" -Append | Set-ColorWhite
}

# List all Scheduled Tasks
#
function Get-ScheduledTasks {
    Write-Output '[*] Scheduled Tasks' | Tee-Object -File "$Env:COMPUTERNAME-ScheduledTasksReport.txt" -Append | Set-ColorMagenta
    Write-Output '-----------------------' | Tee-Object -File "$Env:COMPUTERNAME-ScheduledTasksReport.txt" -Append | Set-ColorMagenta
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-ScheduledTasksReport.txt" -Append | Set-ColorWhite
    schtasks /query /fo LIST /v | Tee-Object -File "$Env:COMPUTERNAME-ScheduledTasksReport.txt" -Append | Set-ColorWhite
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-ScheduledTasksReport.txt" -Append | Set-ColorWhite
}

# List tasklist of current processes
#
function Get-VerboseTasklist {
    Write-Output '[*] Tasklist (Verbose Info)' | Tee-Object -File "$Env:COMPUTERNAME-TasklistReport.txt" -Append | Set-ColorMagenta
    Write-Output '---------------------------' | Tee-Object -File "$Env:COMPUTERNAME-TasklistReport.txt" -Append | Set-ColorMagenta
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-TasklistReport.txt" -Append | Set-ColorWhite
    tasklist /V /FO List | Tee-Object -File "$Env:COMPUTERNAME-TasklistReport.txt" -Append | Set-ColorWhite
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-TasklistReport.txt" -Append | Set-ColorWhite
}

# Get tasklist with associated service processes.
#
function Get-TasklistbyService {
    Write-Output '[*] Tasklist (by Service)' | Tee-Object -File "$Env:COMPUTERNAME-TasklistReport.txt" -Append | Set-ColorMagenta
    Write-Output '---------------------------' | Tee-Object -File "$Env:COMPUTERNAME-TasklistReport.txt" -Append | Set-ColorMagenta
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-TasklistReport.txt" -Append | Set-ColorWhite
    tasklist /SVC /FO List | Tee-Object -File "$Env:COMPUTERNAME-TasklistReport.txt" -Append | Set-ColorWhite
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-TasklistReport.txt" -Append | Set-ColorWhite
}

# List all startup items. Items in this list should be checked
# against the output of Sysinternals AutoStarts.
function Get-StartupItems {
    Write-Output '[*] Startup Items ' | Tee-Object -File "$Env:COMPUTERNAME-StartupItemsReport.txt" -Append | Set-ColorMagenta
    Write-Output '---------------------------' | Tee-Object -File "$Env:COMPUTERNAME-StartupItemsReport.txt" -Append | Set-ColorMagenta
    wmic startup list full | Tee-Object -File "$Env:COMPUTERNAME-StartupItemsReport.txt" -Append | Set-ColorWhite
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-StartupItemsReport.txt" -Append | Set-ColorWhite
    Write-Output "Verfiy this list against the output of Sysinternals AutoStarts program." | Tee-Object -File "$Env:COMPUTERNAME-StartupItemsReport.txt" -Append | Set-ColorRed
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-StartupItemsReport.txt" -Append | Set-ColorWhite
}

# List installed software.
#
function Get-InstalledSoftware {
    Write-Output '[*] Installed Programs ' | Tee-Object -File "$Env:COMPUTERNAME-InstalledSoftwareReport.txt" -Append | Set-ColorMagenta
    Write-Output '---------------------------' | Tee-Object -File "$Env:COMPUTERNAME-InstalledSoftwareReport.txt" -Append | Set-ColorMagenta
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-InstalledSoftwareReport.txt" -Append | Set-ColorWhite
    Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Sort-Object Publisher, DisplayName, DisplayVersion, InstallDate | Format-Table -AutoSize -Wrap| Tee-Object -File "$Env:COMPUTERNAME-InstalledSoftwareReport.txt" -Append | Set-ColorWhite
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-InstalledSoftwareReport.txt" -Append | Set-ColorWhite
}

# List all installed drivers.
#
function Get-InstalledDrivers {
    Write-Output '[*] Installed Drivers ' | Tee-Object -File "$Env:COMPUTERNAME-InstalledDriversReport.txt" -Append | Set-ColorMagenta
    Write-Output '---------------------------' | Tee-Object -File "$Env:COMPUTERNAME-InstalledDriversReport.txt" -Append | Set-ColorMagenta
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-InstalledDriversReport.txt" -Append | Set-ColorWhite
    wmic sysdriver list full | Tee-Object -File "$Env:COMPUTERNAME-InstalledDriversReport.txt" -Append | Set-ColorWhite
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-InstalledDriversReport.txt" -Append | Set-ColorWhite
}

# List the order drivers are loaded
#
function Get-DriverLoadOrder {
    Write-Output '[*] Driver Load Order ' | Tee-Object -File "$Env:COMPUTERNAME-InstalledDriversReport.txt" -Append | Set-ColorMagenta
    Write-Output '---------------------------' | Tee-Object -File "$Env:COMPUTERNAME-InstalledDriversReport.txt" -Append | Set-ColorMagenta
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-InstalledDriversReport.txt" -Append | Set-ColorWhite
    wmic loadorder list full | Tee-Object -File "$Env:COMPUTERNAME-InstalledDriversReport.txt" -Append | Set-ColorWhite
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-InstalledDriversReport.txt" -Append | Set-ColorWhite
}

# List the Prefetch data located in C:\Windows\Pretch
#
function Get-PrefetchData {
    Write-Output '[*] Prefetch Data ' | Tee-Object -File "$Env:COMPUTERNAME-InstalledSoftwareReport.txt" -Append | Set-ColorMagenta
    Write-Output '---------------------------' | Tee-Object -File "$Env:COMPUTERNAME-InstalledSoftwareReport.txt" -Append | Set-ColorMagenta
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-InstalledSoftwareReport.txt" -Append | Set-ColorWhite
    Get-ChildItem $env:WINDIR\Prefetch |Sort-Object LastWriteTime | select-object Name,FullName,CreationTime,LastAccessTime,LastWriteTime,Mode | Format-List | Tee-Object -File "$Env:COMPUTERNAME-InstalledSoftwareReport.txt" -Append | Set-ColorWhite
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-InstalledSoftwareReport.txt" -Append | Set-ColorWhite
}

# List process name associated with IP connection (requires elevated privileges)
function Get-RemoteProcesses {
    Write-Output '[*] Processes with Remote Connection ' | Tee-Object -File "$Env:COMPUTERNAME-RemoteProcessesReport.txt" -Append | Set-ColorMagenta
    Write-Output '-------------------------------------' | Tee-Object -File "$Env:COMPUTERNAME-RemoteProcessesReport.txt" -Append | Set-ColorMagenta
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-RemoteProcessesReport.txt" -Append | Set-ColorWhite
    netstat -anb | Tee-Object -File "$Env:COMPUTERNAME-RemoteProcessesReport.txt" -Append | Set-ColorWhite
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-RemoteProcessesReport.txt" -Append | Set-ColorWhite
}

# List installed services.

function Get-InstalledServices {
    Write-Output '[*] Installed Services    ' | Tee-Object -File "$Env:COMPUTERNAME-InstalledServicesReport.txt" -Append | Set-ColorMagenta
    Write-Output '--------------------------' | Tee-Object -File "$Env:COMPUTERNAME-InstalledServicesReport.txt" -Append | Set-ColorMagenta
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-InstalledServicesReport.txt" -Append | Set-ColorWhite
    Get-Service | Sort-Object -Property Status, DisplayName -Descending | Format-Table @{L='Display Name';E={$_.DisplayName}}, Status -wrap| Tee-Object -File "$Env:COMPUTERNAME-InstalledServicesReport.txt" -Append | Set-ColorWhite
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-InstalledServicesReport.txt" -Append | Set-ColorWhite
}

##################################################################################################################################
#                 NETWORKING INFORMATION FUNCTIONS
# ---------------------------------------------------------------------
# Basic Network information.
function Get-BasicNetworking {
    Write-Output '[*] Basic Networking Info ' | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorBlue
    Write-Output '--------------------------' | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorBlue
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorWhite
    Get-WmiObject win32_networkadapterconfiguration | Format-List -Property Caption,IPAddress,MACAddress | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorWhite    
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorWhite
}
# List Routing Table information.
function Get-RoutingTable {
    Write-Output '[*] Route Table  ' | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorBlue
    Write-Output '--------------------------' | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorBlue
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorWhite
    Get-WmiObject win32_networkadapterconfiguration | Format-Table -Property Caption,IPAddress,MACAddress -Wrap| Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorWhite  
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorWhite
}

# List Open Ports.
function Get-OpenPorts {
    Write-Output '[*] Open Ports  ' | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorBlue
    Write-Output '--------------------------' | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorBlue
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorWhite
    Get-NetTCPConnection | Sort-Object -Property State,RemoteAddress |Format-Table -Property LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess -AutoSize -Wrap | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorWhite
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorWhite
}

# List Firewall Rules.
function Get-FirewallRules {
    Write-Output '[*] Firewall Profile Settings  ' | Tee-Object -File "$Env:COMPUTERNAME-FirewallReport.txt" -Append
    Write-Output '-------------------------------' | Tee-Object -File "$Env:COMPUTERNAME-FirewallReport.txt" -Append
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-FirewallReport.txt" -Append
    netsh advfirewall show allprofiles | Tee-Object -File "$Env:COMPUTERNAME-FirewallReport.txt" -Append
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-FirewallReport.txt" -Append
    Write-Output '[*] Active Firewall Rules  ' | Tee-Object -File "$Env:COMPUTERNAME-FirewallReport.txt" -Append
    Write-Output '--------------------------'| Tee-Object -File "$Env:COMPUTERNAME-FirewallReport.txt" -Append
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-FirewallReport.txt" -Append
    Get-NetFirewallRule -PolicyStore ActiveStore | Select-Object  -Property  Direction, Enabled, Profile, DisplayName | Format-Table -Property Direction,Enabled,Profile,DisplayName, -Wrap| Tee-Object -File "$Env:COMPUTERNAME-FirewallReport.txt" -Append
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-FirewallReport.txt" -Append
}

# List contents of the hosts file.
function Get-EtcHosts {
    Write-Output '[*] Host File Contents    ' | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorBlue
    Write-Output '--------------------------' | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorBlue
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorWhite
    Get-Content C:\Windows\System32\drivers\etc\hosts | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorWhite
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorWhite
}

# List system DNS cache.
function Get-DNSCache {
    Write-Output '[*] DNS Cache    ' | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorBlue
    Write-Output '--------------------------' | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorBlue
    ipconfig /displaydns | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorWhite
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorWhite
}

# List contents of the hosts arp cache.
function Get-ARPCache {
    Write-Output '[*] ARP Cache    ' | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorBlue
    Write-Output '--------------------------' | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorBlue
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorWhite
    arp -a | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorWhite
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorWhite
}

function Get-LocalShares {
    Write-Output '[*] Local Shares    ' | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorBlue
    Write-Output '--------------------------' | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorBlue
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorWhite
    get-WmiObject -class Win32_Share | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorWhite
    Write-Output "" | Tee-Object -File "$Env:COMPUTERNAME-NetworkingReport.txt" -Append | Set-ColorWhite
}


function Start-Inventory {
    Get-SystemInfo
    Get-Users
    Get-InstalledSoftware
    Get-InstalledServices
    Get-BasicNetworking
    Get-FirewallRules
    Get-OpenPorts
    Get-RoutingTable
    Get-EtcHosts
}

function Start-IR {
    Get-SystemInfo
    Get-MD5Hash
    Get-SHA256Hash
    Get-SuspiciousFiles
    Get-RemoteProcesses
    Get-Users
    Get-UserDirectories
    Get-LoadedDlls
    Get-ScheduledTasks
    Get-VerboseTasklist
    Get-TasklistbyService
    Get-InstalledServices
    Get-StartupItems
    Get-InstalledSoftware
    Get-PrefetchData
    Get-InstalledDrivers
    Get-DriverLoadOrder
    Get-BasicNetworking
    Get-RoutingTable
    Get-OpenPorts
    Get-EtcHosts
    Get-DNSCache
    Get-ARPCache
    Get-LocalShares
    Get-FirewallRules 
}

function Start-InventoryReport {
    $global:LocalDirectory=Get-Location
    $global:ReportDirectory="$global:LocalDirectory\$env:COMPUTERNAME-InventoryReports-$global:date"
    $global:FinalReportDirectory="$global:ReportDirectory\$env:COMPUTERNAME-FinalInventoryReports"
    if (-not (Test-Path -LiteralPath $global:ReportDirectory)) {
        try {
            New-Item -Path "$global:ReportDirectory" -ItemType Directory -ErrorAction Stop | Out-Null #-Force
            mkdir "$global:FinalReportDirectory"
            Move-Item  -Path "$global:LocalDirectory\$env:COMPUTERNAME-*" -Destination $global:ReportDirectory -Exclude "*-InventoryReports-*","*-IncidentReports-*" -ErrorAction SilentlyContinue
        function Get-InventoryReports {
            Get-Content "$global:ReportDirectory\$env:computername-SystemInfo.txt","$global:ReportDirectory\$env:computername-UserReport.txt","$global:ReportDirectory\$env:computername-NetworkingReport.txt",
            "$global:ReportDirectory\$env:computername-FirewallReport.txt","$global:ReportDirectory\$env:computername-InstalledServicesReport.txt",
            "$global:ReportDirectory\$env:computername-InstalledSoftwareReport.txt" | Add-Content $global:FinalReportDirectory\"$env:computername-SystemInventoryReport-$global:date.txt"
        }
        Get-InventoryReports
        }
        catch {
            Write-Error -Message "Unable to create directory '$global:ReportDirectory'. Error was: $_" -ErrorAction Stop
        }
    }
}

function Start-IncidentReport {
    $global:LocalDirectory=Get-Location
    $global:ReportDirectory="$global:LocalDirectory\$env:COMPUTERNAME-IncidentReports-$global:date"
    $global:FinalReportDirectory="$global:ReportDirectory\$env:COMPUTERNAME-FinalIncidentReport"
    if (-not (Test-Path -LiteralPath $global:ReportDirectory)) {
        try {
            New-Item -Path "$global:ReportDirectory" -ItemType Directory -ErrorAction Stop | Out-Null #-Force
            mkdir "$global:FinalReportDirectory"
            Move-Item  -Path "$global:LocalDirectory\$env:COMPUTERNAME-*" -Destination $global:ReportDirectory -Exclude "*-IncidentReports-*" -ErrorAction SilentlyContinue
            function Get-IRReports {
                Get-Content "$global:ReportDirectory\$env:computername-SystemInfo.txt","$global:ReportDirectory\$env:computername-UserReport.txt","$global:ReportDirectory\$env:computername-NetworkingReport.txt",
                "$global:ReportDirectory\$env:computername-FirewallReport.txt","$global:ReportDirectory\$env:computername-InstalledServicesReport.txt","$global:ReportDirectory\$env:computername-TasklistReport.txt",
                "$global:ReportDirectory\$env:computername-InstalledSoftwareReport.txt","$global:ReportDirectory\$env:computername-InstalledDriversReport.txt","$global:ReportDirectory\$env:computername-LoadedDllsReport.txt",
                "$global:ReportDirectory\$env:computername-StartupItemsReport.txt","$global:ReportDirectory\$env:computername-ScheduledTasksReport.txt",
                "$global:ReportDirectory\$env:computername-RemoteProcessesReport.txt","$global:ReportDirectory\$env:computername-SuspiciousFiles.txt",
                "$global:ReportDirectory\$env:computername-MD5SystemHashes.txt","$global:ReportDirectory\$env:computername-SHA256SystemHashes.txt" | Add-Content "$global:FinalReportDirectory\$env:computername-SystemIncidentReport-$global:date.txt"
                }
        Get-IRReports
        }
        catch {
            Write-Error -Message "Unable to create directory '$global:ReportDirectory'. Error was: $_" -ErrorAction Stop
        }
    }
}


        if ($ScanType -eq "Inventory") {
            Start-Inventory
            Start-InventoryReport
            if ($DestinationEmail -ne $null) {
                Send-InventoryReport $SourceEmail $DestinationEmail
            }
        }
        elseif ($ScanType -eq "Incident") {
            Start-IR
            Start-IncidentReport
            if ($DestinationEmail -ne $null) {
            Send-IncidentReport $SourceEmail $DestinationEmail
            }
        }
}
