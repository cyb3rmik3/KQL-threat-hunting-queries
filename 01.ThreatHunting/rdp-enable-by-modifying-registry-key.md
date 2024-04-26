# RDP enable by modifying registry key

### Description

Attackers can attempt to enable RDP, including leveraging multiple living-off-the-land tools. Once RDP is enabled, it allows the attackers to use any number of dual-use tools that leverage the RDP protocol. The following query will hunt for an attempt to enable RDP by simply modifying a registry key.

### References
- https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ransomware-data-exfiltration

### Microsoft Defender XDR
```
let rdpcommands = dynamic([@"fDenyTSConnections", @"REG_DWORD /d 0"]);
DeviceProcessEvents
| where FileName has @"reg.exe"
| where ProcessCommandLine has_all (rdpcommands)
| project DeviceId, DeviceName, ProcessCommandLine, Start = Timestamp
| join kind = inner (DeviceRegistryEvents
| where RegistryKey == @"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Terminal Server"
| where RegistryValueName == @"fDenyTSConnections"
| where ActionType == @"RegistryValueSet"
| where RegistryValueData == @"0"
| where InitiatingProcessFileName == @"reg.exe"
| project DeviceId, End = Timestamp)
on DeviceId
| where (End - Start) between (0min .. 1min)
| project Start, DeviceId, DeviceName, ProcessCommandLine
```

### MITRE ATT&CK Mapping
- Tactic: Defense Evasion
- Technique ID: T1112
- [Modify Registry](https://attack.mitre.org/techniques/T1112/)

### Source
- Microsoft Defender for Endpoint

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 26/04/2024    | Initial publish                   |
