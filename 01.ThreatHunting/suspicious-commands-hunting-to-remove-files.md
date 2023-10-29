# Suspicious commands hunting to remove files

### Description

Recent analyses published, uncovered DarkGate operators removing malicious indicators. The followinq query has derived from malware analysis, however it should be considered as low precision hunting method and should be fine tuned based on your environment to achieve high precision. 

### References
- https://threatfox.abuse.ch/ioc/1152536/
- https://twitter.com/fr0s7_/status/1712218958282063898/photo/1

### Microsoft 365 Defender & Microsoft Sentinel
```
let Timeframe = 1d; // Choose the best timeframe for your investigation
DeviceProcessEvents
| where Timestamp > ago(Timeframe)
| where ProcessCommandLine contains "&& rmdir" and ProcessCommandLine contains "&& del"
| project Timestamp, DeviceName, FileName, FolderPath, SHA256, ProcessVersionInfoFileDescription, ProcessCommandLine, AccountName, InitiatingProcessParentFileName
```

### MITRE ATT&CK Mapping
- Tactic: T1070.004
- Technique ID: T1070.004
- [Indicator Removal: File Deletion](https://attack.mitre.org/techniques/T1070/004/)

### Source

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 29/10/2023    | Initial publish                   |
