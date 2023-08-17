# PowerShell spawning MSHTA & initiating remote connection

### Description

MSHTA is heavily used by adversaries as it allows to execute arbitrary code using a Windows native application. A scenario observed includes powershell.exe spawning mshta.exe which by itself is suspicious but it is almost certainly malicious when a remote call initiates through an .hta file. The following query will track powershell spawning mshta initiating a remote connection.

### References
- https://redcanary.com/threat-detection-report/techniques/mshta/
- https://twitter.com/Kostastsale/status/1691302618037903363

### Microsoft 365 Defender & Microsoft Sentinel
```
let Process = DeviceProcessEvents
| where InitiatingProcessParentFileName has_any (@"powershell.exe", @"pwsh.exe", @"powershell_ise.exe") 
| where InitiatingProcessFileName has @"mshta.exe"
| project Timestamp, DeviceName, AccountDomain, AccountName;
Process
    | join (DeviceNetworkEvents
    | where RemoteIP !has "" or RemoteUrl !has ""
    | project DeviceName, RemoteIP, RemoteUrl
) on DeviceName
```

### MITRE ATT&CK Mapping
- Tactic: Defence evasion
- Technique ID: T1218.005
- [System Binary Proxy Execution: Mshta](https://attack.mitre.org/techniques/T1218/005/)

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 16/08/2023    | Initial publish                   |
