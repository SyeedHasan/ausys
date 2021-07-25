@REM
@REM Advanced Audit Policy Configuration Checker by Ebryx (Pvt. Ltd)
@REM Date: 20-10-2020
@REM Version: 0.1
@REM Description: Check the current status of advanced audit policy configurations in the system
@REM Pre-requisites: Requires admin privileges to execute
@REM 

cls
@echo off

echo.
echo.
echo Audit Configuration Checker by Ebryx (Pvt.) Ltd. 
echo.
echo.

@REM 
@REM Admin Privilege Check
@REM 
goto adminCheck
:adminCheck
    echo [+] Administrative permissions required to execute the script. Checking for them now...

    @REM Since the command requires administrator privileges, the execution's 'errorlevel' will decide the operation
    net session >nul 2>&1
    if %errorLevel% == 0 (
        echo [+] Success: Administrative rights are available
    ) else (
        echo [-] Failure: Current permissions inadequate to execute the script. Please re-run the console window as an administrator or execute the script as such...
        echo [-] Exiting the window...
        timeout 5
        Exit /B 1
    )

set host=%COMPUTERNAME%

@REM 
@REM Return audit policy configurations 
@REM 
echo [+] Checking advanced audit policy configurations via 'auditpol'
auditpol.exe /get /Category:* > %host%_sys_auditpol.txt

@REM 
@REM Return PowerShell based logging
@REM 
echo [+] Retrieving PowerShell logging status from the Registry
echo Module Logging Status: > %host%_powershell_logging.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" >> %host%_powershell_logging.txt
echo. >> %host%_powershell_logging.txt
echo Script-block Logging Status: >> %host%_powershell_logging.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" >> %host%_powershell_logging.txt
echo. >> %host%_powershell_logging.txt
echo Transcription Status for PowerShell: >> %host%_powershell_logging.txt
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" >> %host%_powershell_logging.txt

@REM 
@REM Return audit settings 
@REM 
echo [+] Retrieving audit trail of the system from the Registry 
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" > %host%_auditsettings.txt

@REM 
@REM Checking log sources
@REM 
echo [+] Retrieving information about log sources
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

@REM 
@REM Execution Completed
@REM 
echo.
echo [+] Execution complete.
echo [+] Please handover the files to Ebryx DFIR team for a review...