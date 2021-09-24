Write-Host "
   ___                  
  / _ |__ _____ __ _____
 / __ / // (_-</ // (_-<
/_/ |_\_,_/___/\_, /___/
              /___/     

Author: Syed Hasan
Version: 3.0
"

function setupSysmon {
    # Pull Sysmon
    Invoke-WebRequest -Uri https://download.sysinternals.com/files/Sysmon.zip -OutFile $env:TEMP\Sysmon.zip
    Expand-Archive -Path $env:TEMP\Sysmon.zip -DestinationPath $env:TEMP -Force

    # Pull Sysmon's Configuration
    Invoke-WebRequest -Uri https://raw.githubusercontent.com/Neo23x0/sysmon-config/master/sysmonconfig-export.xml -OutFile $env:TEMP\sysmon-config.xml

    # Enable Sysmon
    Start-Process -FilePath powershell.exe -WorkingDirectory $env:TEMP -ArgumentList "-nop -WindowStyle hidden -noexit", ".\Sysmon64.exe", "-accepteula -i .\sysmon-config.xml"
}

function configureAuditLogging {

    reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f

    auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable
    auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
    auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:enable /failure:enable
    auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable

    auditpol /set /subcategory:"Logon" /success:enable /failure:enable
    auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
    auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
    auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
    auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable

    auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:enable
    auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable
    auditpol /set /subcategory:"File Share" /success:enable /failure:enable
}

function enableLogChannels {
    wevtutil sl /q Microsoft-Windows-DNS-Client/Operational /e:true
    wevtutil sl /q Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Admin /e:true
    wevtutil sl /q Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Debug /e:true
    wevtutil sl /q Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational /e:true
    wevtutil sl /q Microsoft-Windows-TerminalServices-LocalSessionManager/Operational /e:true
    wevtutil sl /q Microsoft-Windows-TerminalServices-LocalSessionManager/Admin /e:true
    wevtutil sl /q Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin /e:true
    wevtutil sl /q Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational /e:true
    wevtutil sl /q Microsoft-Windows-TerminalServices-RDPClient/Operational /e:true
    wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
}

function modifyChannelLogSizes {
    wevtutil sl Security /ms:262144000
    wevtutil sl System /ms:262144000
    wevtutil sl Application /ms:262144000
    wevtutil sl "Windows Powershell" /ms:262144000
    wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:262144000
    wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:262144000
}

function disableDuplicatingLogs {
    # Disable Execution Logs from Native Windows
    auditpol /set /subcategory:"Process Creation" /success:disable /failure:disable
    auditpol /set /subcategory:"Process Termination" /success:disable /failure:disable
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /f /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 0

    # Disable 'Object Access' auditing
    auditpol /set /category:"{6997984A-797A-11D9-BED3-505054503030}" /success:disable /failure:disable

    # Disable other auditing
    auditpol /set /category:"Account Management" /success:disable /failure:disable
    auditpol /set /category:"Policy Change" /success:disable /failure:disable
    auditpol /set /category:"Privilege Use" /success:disable /failure:disable

    auditpol /set /subcategory:"Registry" /success:disable
    auditpol /set /subcategory:"Removable Storage" /success:disable /failure:disable    
}

function configurePowerShellLogging {
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell" /f /v ExecutionPolicy /t REG_SZ /d "RemoteSigned"
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /f /v EnableModuleLogging /t REG_DWORD /d 1 
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /f /v EnableScriptBlockLogging /t REG_DWORD /d 1
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /f /v EnableInvocationHeader /t REG_DWORD /d 1
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /f /v EnableTranscripting /t REG_DWORD /d 1
    mkdir $env:USERPROFILE\Documents\PowerShell\Transcripts 
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /f /v OutputDirectory /t REG_SZ /d "$env:USERPROFILE\Documents\PowerShell\Transcripts"
    
}

setupSysmon
disableDuplicatingLogs
configureAuditLogging
enableLogChannels
modifyChannelLogSizes
