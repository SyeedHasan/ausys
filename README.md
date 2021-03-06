
# Ausys
Ausys is a simple batch script which automates viewing the current audit policies of a system. A mode (selected by using the ```enable``` parameter) can also enable selected audit settings on the host system. These audit settings follow best practices and can help an analyst acquire useful logs in a timely manner.

## Execution
```Batch Script:``` Simply execute the batch script using a command prompt with ```administrative privileges``` to view all policies/configurations. \
```PowerShell:``` Simply execute the .ps1 script with Administrative Privileges

### Improve System Auditing
Run the script with the ```enable``` parameter to enable recommended audit policies, log channels, and improving sizing. A short documentation against each change is provided below.

#### Audit Policies
The script seeks to enable the following policies if executed under the ```enable``` mode: 

- Credential Validation
- Kerberos Authentication Service
- Kerberos Service Ticket Operations
- Other Account Logon Events
- Other Logon/Logoff Events
- Account Management [Disabled in V3]
- Logon
- Logoff
- Account Lockout
- Special Logon
- Process Creation
  - Process Command-line 
- Process Termination [Disbaled in V3 in favor of Sysmon]
  - Process Command-line
- PnP Events
- Object Access [Disabled in V3]
  - Removable Storage
  - Registry
  - File Share
    - Detailed File Share

#### Log Channels
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

#### Log Sizing

Increase the log size of the following log channels:
- PowerShell
- Security
- System
- Application
- Sysmon
  - Requires configuring the service beforehand [Already configured in V3]

## Contributions
Please open pull requests to add support for policies, log channels, or otherwise according to best practices. 

## Milestones
- Add support for:  https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5d497aefe58b7e00011f6947/1565096688890/Windows+Registry+Auditing+Cheat+Sheet+ver+Aug+2019.pdf


## Changelog

### Version 3
- Ausys' PowerShell script adds on top of V2 to add support to fetch, configure, and enable Sysmon on the system
  - Configuration for Sysmon is acquired from Florian Roth's fork of SwiftOnSecurit's sysmon configuration