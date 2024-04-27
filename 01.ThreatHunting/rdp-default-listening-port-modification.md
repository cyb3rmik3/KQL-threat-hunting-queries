# RDP default listening port modification

### Description

Changing the default port 3389 to a non-standard port, could indicate a potential APT behaviour to avoid being detected abusing RDP connection.

### References
- https://www.blackhillsinfosec.com/rogue-rdp-revisiting-initial-access-methods/

### Microsoft Defender XDR
```
let Timeframe = 1d; // Choose the best timeframe for your investigation
DeviceRegistryEvents
| where Timestamp > ago(Timeframe)
| where RegistryKey == @"HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp"
| where RegistryValueName == @"PortNumber"
| where RegistryValueData != @"3389"
| where ActionType == @"RegistryValueSet"
| project Timestamp, DeviceName, PreviousRegistryValueName, PreviousRegistryValueData, InitiatingProcessFileName
```

### MITRE ATT&CK Mapping
- Tactic: Command and Control
- Technique ID: T1571
- [Non-Standard Port](https://attack.mitre.org/techniques/T1571/)

### Source
- Microsoft Defender for Endpoint

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 27/04/2024    | Initial publish                   |
