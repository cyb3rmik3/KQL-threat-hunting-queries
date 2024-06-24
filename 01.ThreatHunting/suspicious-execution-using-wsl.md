# Suspicious execution using WSL

### Description

The following query will assist in hunting for suspicious execution using WSL environments at endpoints.

### References


### Microsoft Defender XDR & Microsoft Sentinel
```
let WSLHostSuspicousList = dynamic(["curl", "/etc/shadow", "/etc/passwd", "cat", "--system", "root", "-e", "--exec", "bash", "/mnt/c/"]); 
let TimeFrame = 30d; // Choose the best timeframe for your investigation
DeviceProcessEvents
    | where Timestamp > ago(TimeFrame)
    | where InitiatingProcessFileName has "wsl.exe"
    | where ProcessCommandLine has_any (WSLHostSuspicousList)
    | project TimeGenerated, DeviceId, DeviceName, FileName, FolderPath, ProcessId, ProcessCommandLine, AccountDomain, AccountName
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
