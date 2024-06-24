# Suspicious reconnaissance activity through WSL

### Description

The following query will assist in hunting for suspicious activity similar to reconnaissance in WSL environments at endpoints.

### References


### Microsoft Defender XDR & Microsoft Sentinel
```
let WSLSuspicousList = dynamic(["whoami", "uname", "find", "grep", "cron -l", "/etc/shadow", "/etc/passwd", "/etc/sudoers", "w"]); 
let TimeFrame = 30d; // Choose the best timeframe for your investigation
DeviceInfo
    | where RegistryDeviceTag has "WSL2"
    | project DeviceId
| join ( DeviceProcessEvents
    | where Timestamp > ago(TimeFrame)
    | where ActionType == "ProcessCreated"
    | where ProcessCommandLine has_any (WSLSuspicousList)
    | project TimeGenerated, WSLDeviceID = DeviceId, DeviceName, FileName, FolderPath, ProcessId, ProcessCommandLine, AccountDomain, AccountName
    )
on $left.DeviceId == $right.WSLDeviceID
| sort by TimeGenerated desc
```


### MITRE ATT&CK Mapping
- Tactic: Defense Evasion
- Technique ID: T1202
- [Indirect Command Execution](https://attack.mitre.org/techniques/T1204/001/)

### Source
- MDE

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 24/06/2024    | Initial publish                   |
