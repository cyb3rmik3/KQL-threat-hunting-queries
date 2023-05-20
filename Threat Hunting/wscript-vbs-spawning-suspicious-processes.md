 GULOADER
# WScript to VBS file invoking PowerShell

### Description

This hunting query is based on a GULOADER payload delivered through a .vbs file which invoked PowerShell to gain foothold on the device.

### References
- https://www.virustotal.com/gui/file/dc0b4a1c978fee4d876b50912477445498b44b9f10efdd0f43eae64612f90c0a
- https://www.virustotal.com/gui/file/5b5eda30397c73f6f55070507ec1a745b161ebbfdab09ab340c0ad7583c59c90

### Microsoft 365 Defender
```
DeviceProcessEvents
// Define the time you are interested to look into
| where Timestamp > ago(1d)
| where InitiatingProcessParentFileName contains @"wscript.exe"
// Command line includes VBS file execution
| where InitiatingProcessCommandLine contains ".vbs"
// Invoking PowerShell or Command Line
| where InitiatingProcessFileName has_any (@"powershell.exe", @"pwsh.exe", @"powershell_ise.exe", @"cmd.exe")
// Define elements that should be available in the results
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName 
```

### Microsoft Sentinel
```
DeviceProcessEvents
// Define the time you are interested to look into
| where TimeGenerated > ago(1d)
| where InitiatingProcessParentFileName contains @"wscript.exe"
// Command line includes VBS file execution
| where InitiatingProcessCommandLine contains ".vbs"
// Invoking PowerShell or Command Line
| where InitiatingProcessFileName has_any (@"powershell.exe", @"pwsh.exe", @"powershell_ise.exe", @"cmd.exe")
// Define elements that should be available in the results
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName 
```

### MITRE ATT&CK Mapping
- Tactic: Execution
- Technique ID: T1059
- [Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)

### Source
- MDE

### Versioning
| Version       | Date          | Comments                      |
| ------------- |---------------| ------------------------------|
| 1.0           | 17/02/2023    | Initial publish               |
| 1.1           | 20/05/2023    | Modified template, ATT&CK map |

