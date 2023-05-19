# Identify MITRE ATT&CK Techniques

## Description

Description

## References
- https://attack.mitre.org/techniques/enterprise/

### Microsoft 365 Defender
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
