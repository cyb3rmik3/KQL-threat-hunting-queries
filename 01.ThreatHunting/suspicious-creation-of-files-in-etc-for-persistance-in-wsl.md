# Suspicious creation of files in /etc for persistence in WSL

### Description

The following query will assist in hunting for suspicious creation of files in /etc for persistence in WSL environments at endpoints.

### References


### Microsoft Defender XDR & Microsoft Sentinel
```
let LinuxPerSuspicousCommands = dynamic(["/etc/ld.so.conf.d/", "/etc/cron.d/", "/etc/sudoers.d/", "/etc/rc.d/init.d/", "/etc/systemd/system/","/usr/lib/systemd/system/"]);
let TimeFrame = 30d; // Choose the best timeframe for your investigation
DeviceInfo
    | where RegistryDeviceTag has "WSL2"
    | project DeviceId
| join ( DeviceFileEvents
    | where Timestamp > ago(TimeFrame)
    | where ActionType == "FileCreated"
    | where FolderPath has_any (LinuxPerSuspicousCommands)
    | project TimeGenerated, WSLDeviceID = DeviceId, DeviceName, FileName, FolderPath
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
