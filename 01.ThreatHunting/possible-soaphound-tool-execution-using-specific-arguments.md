# Possible SOAPHound Tool execution using specific arguments

### Description

SOAPHound is a custom-developed .NET data collector tool which can be used to enumerate Active Directory environments via the Active Directory Web Services (ADWS) protocol. The following query will detect possible SOAPHound activity, based on the execution options, and relevant arguments.

### References
- https://github.com/FalconForceTeam/SOAPHound
- https://github.com/tsale/Sigma_rules/blob/main/windows_exploitation/SOAPHound.yml

### Microsoft Defender XDR & Sentinel
```
DeviceProcessEvents
| where ProcessCommandLine has_any (" --buildcache "," --bhdump ", " --certdump "," --dnsdump ")
  and ProcessCommandLine has_any (" -c "," --cachefilename ", " -o "," --outputdirectory")
```

### MITRE ATT&CK Mapping
- Tactic: Discovery
- Technique ID: T1087
- [Account Discovery](https://attack.mitre.org/techniques/T1087/)

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 27/01/2024    | Initial publish                   |
