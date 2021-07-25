
# Ausys
Ausys is a simple batch script which automates viewing the current audit policies of a system. A mode (selected by using the ```enable``` parameter) can also enable selected audit settings on the host system. These audit settings follow best practices and can help an analyst acquire useful logs in a timely manner.

## Improve System Auditing
Run the script with the ```enable``` parameter to enable enable several audit policies and log channels discussed below.

### Audit Policies
The script seeks to enable the following policies if executed under the ```enable``` mode: 
- Logon
- Logoff
- Account Lockout
- Special Logon
- Process Creation
  - Process Command-line 
- Process Termination
  - Process Command-line
- PnP Events
- Removable Storage

### Log Channels
The script will also enable the following log channels if executed under the ```enable``` mode:
- Remote Desktop Services
  - RdpCoreTS
- Terminal Services
  - Local Session Manager
  - Remote Connection Manager
  - RDP Client
- Task Scheduler