@REM
@REM Ausys - An Advanced Audit Policy Configuration Checker
@REM Author: Syed Hasan
@REM Date: 29-07-2021
@REM Version: 2.2
@REM Description: Check the current status of advanced audit policy configurations in the system
@REM Pre-requisites: Requires admin privileges to execute
@REM 

cls
@echo off
setlocal EnableExtensions EnableDelayedExpansion

:::
:::   ___                  
:::  / _ |__ _____ __ _____
::: / __ / // (_-</ // (_-<
:::/_/ |_\_,_/___/\_, /___/
:::              /___/     
:::

for /f "delims=: tokens=*" %%A in ('findstr /b ::: "%~f0"') do @echo(%%A

echo An Audit Configuration Checker
echo.

@REM 
@REM Admin Privilege Check
@REM 
goto adminCheck
:adminCheck
    echo Administrator Privilege Check
    echo [+] Administrative permissions required to execute the script. Checking for required privileges now...
    
    @REM Since the command requires administrator privileges, the execution's 'errorlevel' will decide the operation
    net session >nul 2>&1
    if %errorLevel% == 0 (
        echo [+] SUCCESS: Administrative privileges are available.
        echo [+] Continuing the script's execution
        echo.
    ) else (
        echo [-] Failure: Current permissions are inadequate to execute the script. Please re-run the console window as an administrator or execute the script as such...
        echo [-] Halting the script's execution... 
        timeout 5
        Exit /B 1
    )

set host=%COMPUTERNAME%

if "%1" EQU "enable" (
    echo  Enabling Advanced Audit Logging and Log Channels 
    echo [+] Executing 'enable' mode
    echo [+] Forcing Advanced Audit Logging via SCENoApplyLegacyAuditPolicy [0m
    reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f > nul

    echo [+] Setting Audit Policies

    auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable >nul
    auditpol /set /subcategory:"Kerberos Authentication Service" /success:disable /failure:disable >nul
    auditpol /set /subcategory:"Kerberos Service Ticket Operations" /success:disable /failure:disable >nul
    auditpol /set /subcategory:"Other Account Logon Events" /success:enable /failure:enable >nul

    auditpol /set /subcategory:"Logon" /success:enable /failure:enable >nul
    auditpol /set /subcategory:"Logoff" /success:enable /failure:disable >nul
    auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable >nul
    auditpol /set /subcategory:"Special Logon" /success:enable /failure:disable >nul
    auditpol /set /subcategory:"Other Logon/Logoff Events" /success:enable /failure:enable >nul

    auditpol /set /category:"Account Management" /success:disable /failure:disable >nul

    auditpol /set /subcategory:"Detailed File Share" /success:enable >nul
    auditpol /set /subcategory:"File Share" /success:enable >nul
    auditpol /set /subcategory:"Registry" /success:enable >nul

    Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable >nul
    Auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable >nul
    Auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:enable >nul
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /f /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 >nul
    echo [+] Process Execution auditing enabled

    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell" /f /v ExecutionPolicy /t REG_SZ /d "RemoteSigned" >nul
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /f /v EnableModuleLogging /t REG_DWORD /d 1 >nul 
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /f /v EnableScriptBlockLogging /t REG_DWORD /d 1 >nul
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /f /v EnableInvocationHeader /t REG_DWORD /d 1 >nul
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /f /v EnableTranscripting /t REG_DWORD /d 1 >nul
    mkdir %USERPROFILE%\Documents\PowerShell\Transcripts 2>nul 
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /f /v OutputDirectory /t REG_SZ /d "%USERPROFILE%\Documents\PowerShell\Transcripts" >nul
    echo [+] PowerShell auditing enabled [Module Logging, ScriptBlockLogging, Transcriptions] 

    auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable >nul
    echo [+] Removable Storage auditing enabled
    
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
    echo [+] Enabled Log Sources: Task Scheduler, RDP, TerminalServices, DNS

    echo [+] Setting Log Channel Sizes to 250MB+
    wevtutil sl Security /ms:262144000
    wevtutil sl System /ms:262144000
    wevtutil sl Application /ms:262144000
    wevtutil sl "Windows Powershell" /ms:262144000
    wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:262144000
    wevtutil sl "Microsoft-Windows-Sysmon/Operational" /ms:262144000

    @REM 
    @REM Execution Completed
    @REM 
    echo.
    echo [+] EXECUTION STATUS: Complete
    echo [+] Audit log settings were also enabled during the execution.

) else (

    @REM 
    @REM Return audit policy configurations 
    @REM 
    echo Advanced Audit Policy Configurations
    echo [+] Acquiring the system's audit policy configurations using 'auditpol.exe'
    auditpol.exe /get /Category:* > %host%_sys_auditpol.txt
    echo [+] Acquired audit policy configurations and saved to disk. Continuing... 
    echo.

    @REM 
    @REM Audit PowerShell-based logging
    @REM 
    echo PowerShell Logging Status
    echo [+] Retrieving PowerShell logging status from the system's Registry hives
    echo Module Logging Status: > %host%_powershell_logging.txt
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" >> %host%_powershell_logging.txt 2>nul
    if %errorlevel%==1 (
        echo Disabled >> %host%_powershell_logging.txt
    )
    echo. >> %host%_powershell_logging.txt
    echo Script-block Logging Status: >> %host%_powershell_logging.txt
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" >> %host%_powershell_logging.txt 2>nul
    if %errorlevel%==1 (
        echo Disabled >> %host%_powershell_logging.txt
    )
    echo. >> %host%_powershell_logging.txt
    echo Transcription Status for PowerShell: >> %host%_powershell_logging.txt
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" >> %host%_powershell_logging.txt 2>nul
    if %errorlevel%==1 (
        echo Disabled >> %host%_powershell_logging.txt
    )
    echo [+] Acquired PowerShell logging status from the system's Registry hives
    echo. 

    @REM 
    @REM Generic Auditing
    @REM 
    echo Audit Trail
    echo [+] Retrieving audit trail of the system from the Registry hives
    echo Audit Settings on the System: > %host%_auditsettings.txt
    reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" >> %host%_auditsettings.txt 2>nul
    if %errorlevel%==1 (
        echo Disabled >> %host%_auditsettings.txt
    )
    echo Advanced Audit Policy: >> %host%_auditsettings.txt
    reg query "HKLM\System\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy >> %host%_auditsettings.txt >nul 2>nul
    if %errorlevel%==1 (
        echo Disabled >> %host%_auditsettings.txt
    )
    echo [+] Acquired audit trail of the sytem and stored to disk 
    echo. 

    @REM 
    @REM Log Source Auditing
    @REM 
    echo Log Channels [Size, Retention Policies, Access Times]
    echo [+] Retrieving key information about log sources using wevtutil
    echo Critical Log Channels: > %host%_gli-logsources.txt
    echo. >> %host%_gli-logsources.txt
    echo Channel: Application >> %host%_gli-logsources.txt
    wevtutil gli Application >> %host%_gli-logsources.txt
    echo. >> %host%_gli-logsources.txt
    echo Channel: Security >> %host%_gli-logsources.txt
    wevtutil gli Security >> %host%_gli-logsources.txt 
    echo. >> %host%_gli-logsources.txt
    echo Channel: System >> %host%_gli-logsources.txt
    wevtutil gli System >> %host%_gli-logsources.txt
    echo. >> %host%_gli-logsources.txt
    echo Channel: Powershell-Admin >> %host%_gli-logsources.txt
    wevtutil gli Microsoft-Windows-PowerShell/Admin >> %host%_gli-logsources.txt
    echo. >> %host%_gli-logsources.txt
    echo Channel: Powershell-Operational >> %host%_gli-logsources.txt
    wevtutil gli Microsoft-Windows-PowerShell/Operational >> %host%_gli-logsources.txt
    echo. >> %host%_gli-logsources.txt
    echo Other Channels: >> %host%_gli-logsources.txt
    echo. >> %host%_gli-logsources.txt

    @REM echo Listing all Log Channels: >> %host%_el-logchannels.txt
    @REM echo. >> %host%_el-logchannels.txt
    @REM wevtutil el >> %host%_el-logchannels.txt 

    @REM FOR /F "tokens=*" %%A in (%host%_el-logchannels.txt) DO (
    @REM     wevtutil gli "%%A" >> %host%_gli-logsources.txt
    @REM     echo. >> %host%_gli-logsources.txt
    @REM     wevtutil gl "%%A" >> %host%_gl-logsources.txt
    @REM     echo. >> %host%_gl-logsources.txt
    @REM )

    echo [+] Acquired key information about log sources and stored to disk
    echo [+] Checking if 'enable' mode is to be executed

    @REM 
    @REM Execution Completed
    @REM 
    echo.
    echo [+] EXECUTION STATUS: Complete.
    echo [-] No audit log settings were enabled during the execution. Re-run the script with the 'enable' parameter to do so.

) 
