
# Ausys
Ausys is a simple batch script which automates viewing the current audit policies of a system. A mode (selected by using the ```enable``` parameter) can also enable selected audit settings on the host system. These audit settings follow best practices and can help an analyst acquire useful logs in a timely manner.

## Improve System Auditing
Run the script with the ```enable``` parameter to enable enable several audit policies and log channels discussed below.

### Audit Policies
The script seeks to enable the following policies if executed under the ```enable``` mode: 

- Credential Validation
- Kerberos Authentication Service
- Kerberos Service Ticket Operations
- Other Account Logon Events
- Other Logon/Logoff Events
- Account Management
- Logon
- Logoff
- Account Lockout
- Special Logon
- Process Creation
  - Process Command-line 
- Process Termination
  - Process Command-line
- PnP Events
- Object Access
  - Removable Storage
  - Registry
- File Share
  - Detailed File Share

### Log Channels
The script will also enable the following log channels if executed under the ```enable``` mode:
- Remote Desktop Services
  - RdpCoreTS
- Terminal Services
  - Local Session Manager
  - Remote Connection Manager
  - RDP Client
- Task Scheduler
- PowerShell
  - Module
  - ScriptBlock
  - Transcriptions

### Log Sizing

Increase the log size of the following log channels:
- PowerShell
- Security
- System
- Application
- Sysmon
  - Requires configuring the service beforehand

## Contributions
Please open pull requests to add support for policies, log channels, or otherwise according to best practices. 