# PowerShell Base64 encoding

### Description

Hunting for Base64 encoded command lines in PowerShell is crucial to detect and mitigate potential cyber threats. While the analytic below will detect Base64 encoded commands, a fine tuning is required for your environment.

### References
- https://redcanary.com/threat-detection-report/techniques/powershell/

### Microsoft 365 Defender & Microsoft Sentinel
```
DeviceProcessEvents
// 
| where Timestamp > ago(1d)
| where FileName has_any (@"powershell.exe", @"pwsh.exe", @"powershell_ise.exe")
| where ProcessCommandLine contains "base64"
| summarize arg_max(Timestamp, *) by DeviceName
```

### MITRE ATT&CK Mapping
- Tactic: Execution
- Technique ID: T1059.001
- [Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)

### Source

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 14/08/2023    | Initial publish                   |
