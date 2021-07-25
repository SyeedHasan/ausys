@REM
@REM Ausys - An Advanced Audit Policy Configuration Checker by Ebryx (Pvt. Ltd)
@REM Date: 20-10-2020
@REM Version: 0.2
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

echo [7mAn Audit Configuration Checker by Ebryx (Pvt.) Ltd.[0m
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
@REM Return PowerShell based logging
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
@REM Return audit settings 
@REM 
echo [7mAudit Trail[0m
echo [92m[+] Retrieving audit trail of the system from the Registry hives[0m
echo Audit Settings on the System: > %host%_auditsettings.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" >> %host%_auditsettings.txt
echo [92m[+] Acquired audit trail of the sytem and stored to disk [0m
echo. 

@REM 
@REM Checking log sources
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

@REM 
@REM Execution Completed
@REM 
echo.
echo [92m[+] EXECUTION STATUS: Complete[0m
echo [92m[+] Analyze results from auditsettings.txt, logsources.txt, powershell_logging.txt, and sys_auditpol.txt for a review of the logging configurations...[0m
timeout 10