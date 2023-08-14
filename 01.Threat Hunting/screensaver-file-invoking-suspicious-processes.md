# Screensaver file invoking suspicious processes

### Description

This hunting query is based on a RedLine stealer malware delivered through a .scr file which invoked a suspicious processes including command prompt, powershell or any other .exe file.

### Microsoft 365 Defender
```
DeviceProcessEvents
| where FileName has_any (@"cmd.exe", @"powershell.exe", @".exe")
| where InitiatingProcessFileName contains ".scr"
| summarize arg_max(Timestamp, *) by DeviceName
| project Timestamp, DeviceName
```

### MITRE ATT&CK Mapping
- Tactic: Persistence
- Technique ID: T1546.002
- [Event Triggered Execution: Screensaver](https://attack.mitre.org/techniques/T1546/002/)

### Source
- MDE

### Versioning
| Version       | Date          | Comments                      |
| ------------- |---------------| ------------------------------|
| 1.0           | 08/11/2022    | Initial publish               |
| 1.1           | 23/05/2023    | Modified template, ATT&CK map |

