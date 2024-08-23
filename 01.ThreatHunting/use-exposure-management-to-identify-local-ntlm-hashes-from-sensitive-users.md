# Use Exposure Management to identify local NTLM hashes from Sensitive Users

### Description

Using the Exposure Management from Defender XDR, the following query with help identify locally available NTLM hashes from users marked as Sensitive.

### Microsoft Defender XDR
```
ExposureGraphEdges
    | where EdgeLabel has "has credentials of"
    | extend parsedData = parse_json(EdgeProperties)
    | extend NTLMHash = parsedData.rawData.ntlmHash.ntlmHash
    | where NTLMHash == "true"
    | project SourceNodeName, SourceNodeLabel, TargetNodeName
| join (IdentityInfo
    | where Tags has "Sensitive"
    | project AccountDisplayName
    )
on $left.TargetNodeName == $right.AccountDisplayName
| summarize by SourceNodeName, SourceNodeLabel, TargetNodeName, AccountDisplayName
```


### MITRE ATT&CK Mapping
- Tactic: Credential Access
- Technique ID: T1003
- [OS Credential Dumping](https://attack.mitre.org/techniques/T1003/)

### Source

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 24/08/2024    | Initial publish                   |
