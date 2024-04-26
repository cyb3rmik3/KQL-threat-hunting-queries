# Network Shell command for firewall to allow incoming RDP connections

### Description

Attackers can attempt to enable RDP, including leveraging multiple living-off-the-land tools. Once RDP is enabled, it allows the attackers to use any number of dual-use tools that leverage the RDP protocol. The following query will hunt for an attempt to create a firewall rule to specifically allow all incoming RDP connections using a Network Shell (netsh) command.

### References
- https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ransomware-data-exfiltration

### Microsoft Defender XDR
```
let Timeframe = 1d; // Choose the best timeframe for your investigation
let fwcommands = dynamic([@"advfirewall", @"firewall", @"add rule", @"dir=in", @"localport=3389", @"action=allow"]);
DeviceProcessEvents
| where Timestamp > ago(Timeframe)
| where FileName has @"netsh.exe"
| where ProcessCommandLine has_all (fwcommands)
| where ActionType has "ProcessCreated"
| project DeviceId, DeviceName, ProcessCommandLine
```

### MITRE ATT&CK Mapping
- Tactic: Impair Defenses
- Technique ID: T1562.004
- [Impair Defenses: Disable or Modify System Firewall](https://attack.mitre.org/techniques/T1204/001/)

### Source
- Microsoft Defender for Endpoint

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 26/04/2024    | Initial publish                   |
