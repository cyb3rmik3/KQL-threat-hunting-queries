# Use Exposure Management to chart User Groups with Local Admin privileges

### Description

Exposure Management offers the capacity to build a map of User Groups that have Local Admin rights on your devices. This could allow identify misconfigurations on privileges assigned to User Groups. You may choose to opt out spcific User Groups which are expected to have local admnin privileges.

### Microsoft Defender XDR
```
//let PriveledgedGroups = dynamic(['', '', '' ]); // Add User Groups that are legitemately allowed to have local admin priveledges on devices
ExposureGraphEdges
| where EdgeLabel == @"can authenticate to"
| where SourceNodeLabel == @"group"
//| where SourceNodeName !in~ (PriveledgedGroups)
| where parse_json(EdgeProperties).rawData.userRightsOnDevice.isLocalAdmin == 'true'
| summarize by SourceNodeName, TargetNodeName
```

### MITRE ATT&CK Mapping
- Tactic: Persistence
- Technique ID: T1098
- [Account Manipulation](https://attack.mitre.org/techniques/T1204/001/)

### Source
- Exposure Management

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 23/08/2024    | Initial publish                   |
