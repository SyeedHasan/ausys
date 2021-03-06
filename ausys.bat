@REM
@REM Ausys - An Advanced Audit Policy Configuration Checker
@REM Author: Syed Hasan
@REM Date: 29-07-2021
@REM Version: 2.2
@REM Description: Check the current status of advanced audit policy configurations in the system
@REM Pre-requisites: Requires admin privileges to execute
@REM 

cls
setlocal EnableExtensions EnableDelayedExpansion
@echo off

:::
:::   ___                  
:::  / _ |__ _____ __ _____
::: / __ / // (_-</ // (_-<
:::/_/ |_\_,_/___/\_, /___/
:::              /___/     
:::

for /f "delims=: tokens=*" %%A in ('findstr /b ::: "%~f0"') do @echo(%%A

echo [7mAn Audit Configuration Checker[0m
echo.

@REM 
@REM Admin Privilege Check
@REM 

goto adminCheck
:adminCheck
    echo [7mAdministrator Privilege Check[0m
    echo [93m[+] Administrative permissions required to execute the script. Checking for required privileges now...[0m
    
    @REM Since the command requires administrator privileges, the execution's 'errorlevel' will decide the operation
    net session >nul 2>&1
    if %errorLevel% == 0 (
        echo [92m[+] SUCCESS: Administrative privileges are available.[0m
        echo [92m[+] Continuing the script's execution[0m
        echo.
    ) else (
        echo [91m[-] Failure: Current permissions are inadequate to execute the script. Please re-run the console window as an administrator or execute the script as such...[0m
        echo [91m[-] Halting the script's execution...[0m 
        timeout 5
        Exit /B 1
    )

set host=%COMPUTERNAME%

if "%1" EQU "enable" (
    echo [7m Enabling Advanced Audit Logging and Log Channels [0m
    echo [92m[+] Executing 'enable' mode[0m
    echo [92m[+] Forcing Advanced Audit Logging via SCENoApplyLegacyAuditPolicy [0m
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

    auditpol /set /subcategory:"Detailed File Share" /success:enable /failure:enable >nul
    auditpol /set /subcategory:"File Share" /success:enable /failure:enable >nul
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
    echo [93m[+] EXECUTION STATUS: Complete[0m
    echo [93m[+] Audit log settings were also enabled during the execution.[0m

) else (

    @REM 
    @REM Return audit policy configurations 
    @REM 
    echo [7mAdvanced Audit Policy Configurations[0m
    echo [92m[+] Acquiring the system's audit policy configurations using 'auditpol.exe'[0m
    auditpol.exe /get /Category:* > %host%_sys_auditpol.txt
    echo [92m[+] Acquired audit policy configurations and saved to disk. Continuing... [0m
    echo.

    @REM 
    @REM Audit PowerShell-based logging
    @REM 
    echo [7mPowerShell Logging Status[0m
    echo [92m[+] Retrieving PowerShell logging status from the system's Registry hives[0m
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
    echo [92m[+] Acquired PowerShell logging status from the system's Registry hives[0m
    echo. 

    @REM 
    @REM Generic Auditing
    @REM 
    echo [7mAudit Trail[0m
    echo [92m[+] Retrieving audit trail of the system from the Registry hives[0m
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
    echo [92m[+] Acquired audit trail of the sytem and stored to disk [0m
    echo. 

    @REM 
    @REM Log Source Auditing
    @REM 
    echo [7mLog Channels [Size, Retention Policies, Access Times][0m
    echo [92m[+] Retrieving key information about log sources using wevtutil[0m
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

    echo [92m[+] Acquired key information about log sources and stored to disk[0m
    echo [92m[+] Checking if 'enable' mode is to be executed[0m

    @REM 
    @REM Execution Completed
    @REM 
    echo.
    echo [93m[+] EXECUTION STATUS: Complete.[0m
    echo [93m[-] No audit log settings were enabled during the execution. Re-run the script with the 'enable' parameter to do so.[0m

)
