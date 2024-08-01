# Exposure management browser cookies with credentials of privileged users

### Description

This hunting query will look in ExposureGraphEdges table for stored credentials, that match users that are privileged.

### Microsoft Defender XDR
```
let PriveledgedRoles = dynamic(['Global Administrator', 'User Administrator']); // Add Entra ID roles you would like to monitor
ExposureGraphEdges
    | where EdgeLabel has "has credentials of"
    | extend parsedData = parse_json(EdgeProperties)
    | extend browserCookies = parsedData.rawData.browserCookies.browserCookies
    | where browserCookies == "true"
    | project SourceNodeName, SourceNodeLabel, TargetNodeName
| join (IdentityInfo
    | mv-expand AssignedRoles
    | where AssignedRoles has_any(PriveledgedRoles)
    | project AccountName
    )
on $left.TargetNodeName == $right.AccountName
```

### MITRE ATT&CK Mapping
- Tactic: Defense Evasion
- Technique ID: T1550.004
- [Use Alternate Authentication Material: Web Session Cookie](https://attack.mitre.org/techniques/T1550/004/)

### Source
- Exposure Management

### Versioning
| Version       | Date          | Comments                      |
| ------------- |---------------| ------------------------------|
| 1.0           | 01/08/2024    | Initial publish               |

