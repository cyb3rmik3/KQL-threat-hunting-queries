# Suspicious rdp files in Outlook temporary folders

### Description

This query is a hunting opportunity following Microsoft's threat intelligence report on Midnight Blizzard spear-phishing campaigns using RDP files. This query will identify *.rdp file creation in Outlook's temporary folders and covers both Windows 10 and Windows 11 OS endpoints.

*Note*: If you have the ["Block Office communication application from creating child processes"](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference#block-office-communication-application-from-creating-child-processes) ASR rule enabled at your environment, endpoint users are forced to save the RDP files before opening and this hunt won't match any data. (Credits: [Ronnie van Buuren](https://www.linkedin.com/in/ronnievanbuuren/))

### References
- https://www.microsoft.com/en-us/security/blog/2024/10/29/midnight-blizzard-conducts-large-scale-spear-phishing-campaign-using-rdp-files/
- https://x.com/cyb3rops/status/1851880158640099675

### Microsoft Sentinel & Microsoft Defender XDR
```
// Following part reflects Windows 10 endpoints
let SuspiciousRdpFilesinOutlookWin10 = DeviceProcessEvents
| where ProcessCommandLine has @'\AppData\Local\Microsoft\' 
    and ProcessCommandLine has @'\Content.Outlook\' 
    and ProcessCommandLine has @'.rdp';
// Following part reflects Windows 11 endpoints
let SuspiciousRdpFilesinOutlookWin11 = DeviceProcessEvents
| where ProcessCommandLine has @'\AppData\Local\Microsoft\Olk\'
    and ProcessCommandLine has @'.rdp';
union SuspiciousRdpFilesinOutlookWin10,
    SuspiciousRdpFilesinOutlookWin11
| project TimeGenerated, 
    DeviceName, 
    ProcessCommandLine, 
    AccountDomain, 
    AccountName
```

### MITRE ATT&CK Mapping
- Tactic: Initial Access
- Technique ID: T1566.001
- [UPhishing: Spearphishing Attachment](https://attack.mitre.org/techniques/T1566/001/)

### Source

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 03/11/2024    | Initial publish                   |
| 1.1           | 04/11/2024    | Description update                |
