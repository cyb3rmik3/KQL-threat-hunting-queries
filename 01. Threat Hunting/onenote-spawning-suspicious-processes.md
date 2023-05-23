# OneNote spawning suspicious processes

### Description

This query detects processes spawned by onenote.exe that could reflect malicious activity. Query has been created during 2/2023 where OneNote has been widely abused to deliver malware.

### References
- https://micahbabinski.medium.com/detecting-onenote-one-malware-delivery-407e9321ecf0
- https://www.rapid7.com/blog/post/2023/01/31/rapid7-observes-use-of-microsoft-onenote-to-spread-redline-infostealer-malware/

### Microsoft 365 Defender & Microsoft Sentinel
```
DeviceProcessEvents
| where InitiatingProcessParentFileName contains @"ONENOTE.EXE"
| where InitiatingProcessFileName has_any (@"powershell.exe", @"pwsh.exe", @"wscript.exe", @"cscript.exe", @"mshta.exe", @"cmd.exe")
```

### MITRE ATT&CK Mapping
- Tactic: Privilege Escalation
- Technique ID: T1055.012
- [Process Injection: Process Hollowing](https://attack.mitre.org/techniques/T1055/012/)

### Source
- MDE

### Versioning
| Version       | Date          | Comments                      |
| ------------- |---------------| ------------------------------|
| 1.0           | 08/02/2023    | Initial publish               |
| 1.1           | 23/05/2023    | Modified template, ATT&CK map |

