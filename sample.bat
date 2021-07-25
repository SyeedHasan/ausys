@ECHO OFF

set host=%COMPUTERNAME%

wevtutil el >> %host%_logchannels.txt 

FOR /F "tokens=*" %%A in (%host%_logchannels.txt) DO ( 
    wevtutil gl %%A | findstr /B /I "enabled: true" 
    if %errorlevel% == 0 (
        echo %%A
    ) else (
        echo A
    )

    @REM FOR /f "tokens=*" %%G IN ('wevtutil gl %%A || findstr /I "enable: true"') DO (
    @REM     echo %%G
    @REM )
)

@REM foreach($line in Get-Content .\%host%_logchannels) {
@REM     if (wevtutil gl $line | Select-String -Pattern "enabled: true" | Where-Object { $_ -match "enabled: true" } ){
@REM     	echo $line
@REM     }
}

exit

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
    echo [92m[+] Audit log settings were enabled during the execution.[0m

) else (
    @REM 
    @REM Execution Completed
    @REM 
    echo.
    echo [92m[+] EXECUTION STATUS: Complete.[0m
    echo [92m[-] No audit log settings were enabled during the execution. Re-run the script with the 'enable' parameter to do so.[0m

) 
