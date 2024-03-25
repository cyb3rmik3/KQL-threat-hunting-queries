# Identify MITRE ATT&CK Techniques

## Description

The following queries provide for Microsoft Sentinel and Microsoft 365 Defender a graphic representation of MITRE ATT&CK techniques from alerts within the timerange defined.

## References
- https://attack.mitre.org/techniques/enterprise/

### Microsoft Defender XDR
```
AlertInfo
// Define timerange
| where Timestamp > ago(30d)
| where AttackTechniques != ""
| mvexpand todynamic(AttackTechniques)
| summarize count() by tostring(AttackTechniques)
// Define graphic
| render piechart 
```
### Microsoft Sentinel
```
SecurityAlert
// Define timerange
| where TimeGenerated > ago(30d)
| where isnotempty(Techniques)
| mvexpand todynamic(Techniques) to typeof(string)
| summarize AlertCount = dcount(SystemAlertId) by Techniques
| sort by AlertCount desc
// Define graphic
| render piechart 
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 01/02/2023    | Initial publish                        |
| 1.1           | 18/05/2023    | Transformed to template, minor changes |
