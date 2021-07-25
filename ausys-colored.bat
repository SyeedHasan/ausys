@REM
@REM Ausys - An Advanced Audit Policy Configuration Checker
@REM Author: Syed Hasan
@REM Date: 25-07-2021
@REM Version: 0.3
@REM Description: Check the current status of advanced audit policy configurations in the system
@REM Pre-requisites: Requires admin privileges to execute
@REM 

cls
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
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" >> %host%_powershell_logging.txt
echo. >> %host%_powershell_logging.txt
echo Script-block Logging Status: >> %host%_powershell_logging.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" >> %host%_powershell_logging.txt
echo. >> %host%_powershell_logging.txt
echo Transcription Status for PowerShell: >> %host%_powershell_logging.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" >> %host%_powershell_logging.txt
echo [92m[+] Acquired PowerShell logging status from the system's Registry hives[0m
echo. 

@REM 
@REM Generic Auditing
@REM 
echo [7mAudit Trail[0m
echo [92m[+] Retrieving audit trail of the system from the Registry hives[0m
echo Audit Settings on the System: > %host%_auditsettings.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" >> %host%_auditsettings.txt
echo [92m[+] Acquired audit trail of the sytem and stored to disk [0m
echo. 

@REM 
@REM Log Source Auditing
@REM 
echo [7mLog Channels [Size, Retention Policies, Access Times][0m
echo [92m[+] Retrieving key information about log sources using wevtutil[0m
echo Channel: Application > %host%_logsources.txt
wevtutil gli Application >> %host%_logsources.txt
echo. >> %host%_logsources.txt
echo Channel: Security >> %host%_logsources.txt
wevtutil gli Security >> %host%_logsources.txt 
echo. >> %host%_logsources.txt
echo Channel: System >> %host%_logsources.txt
wevtutil gli System >> %host%_logsources.txt
echo. >> %host%_logsources.txt
echo Channel: Powershell-Admin >> %host%_logsources.txt
wevtutil gli Microsoft-Windows-PowerShell/Admin >> %host%_logsources.txt
echo. >> %host%_logsources.txt
echo Channel: Powershell-Operational >> %host%_logsources.txt
wevtutil gli Microsoft-Windows-PowerShell/Operational >> %host%_logsources.txt
echo. >> %host%_logsources.txt
echo [92m[+] Acuiqred key information about log sources and stored to disk[0m

if %1%==enable (

    echo [92m[+] Enabling Audit Logging[0m

    auditpol /set /subcategory:"Logon" /success:enable /failure:enable
    auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
    auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable
    auditpol /set /subcategory:"Special Logon" /success:enable /failure:enable
    echo [92m[+] Authentication auditing enabled[0m

    Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
    Auditpol /set /subcategory:"Process Termination" /success:enable /failure:enable
    Auditpol /set /subcategory:"Plug and Play Events" /success:enable /failure:enable
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /f /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1
    echo [92m[+] Process Execution auditing enabled[0m

    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell" /f /v ExecutionPolicy /t REG_SZ /d "RemoteSigned"
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /f /v EnableModuleLogging /t REG_DWORD /d 1
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /f /v EnableScriptBlockLogging /t REG_DWORD /d 1
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /f /v EnableInvocationHeader /t REG_DWORD /d 1
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /f /v EnableTranscripting /t REG_DWORD /d 1
    mkdir %USERPROFILE%\Documents\PowerShell\Transcripts
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /f /v OutputDirectory /t REG_SZ /d "%USERPROFILE%\Documents\PowerShell\Transcripts"
    echo [92m[+] PowerShell auditing enabled [Module Logging, ScriptBlockLogging, Transcription (%USERPROFILE%\Documents\PowerShell\Transcripts)] [0m

    auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
    echo [92m[+] Removable Storage auditing enabled [0m

    wevtutil sl /q Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Admin /e:true
    wevtutil sl /q Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Debug /e:true
    wevtutil sl /q Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational /e:true
    wevtutil sl /q Microsoft-Windows-TerminalServices-LocalSessionManager/Operational /e:true
    wevtutil sl /q Microsoft-Windows-TerminalServices-LocalSessionManager/Admin /e:true
    wevtutil sl /q Microsoft-Windows-TerminalServices-RemoteConnectionManager/Admin /e:true
    wevtutil sl /q Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational /e:true
    wevtutil sl /q Microsoft-Windows-TerminalServices-RDPClient/Operational /e:true
    wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true
    echo [92m[+] Enabled Log Sources: Task Scheduler, RDP, TerminalServices [0m
    @REM 
    @REM Execution Completed
    @REM 
    echo.
    echo [92m[+] EXECUTION STATUS: Complete[0m
    echo [92m[+] Audit log settings were also enabled during the execution.[0m

) else (
    @REM 
    @REM Execution Completed
    @REM 
    echo.
    echo [92m[+] EXECUTION STATUS: Complete.[0m
    echo [92m[-] No audit log settings were enabled during the execution. Re-run the script with the 'enable' parameter to do so.[0m

) 
