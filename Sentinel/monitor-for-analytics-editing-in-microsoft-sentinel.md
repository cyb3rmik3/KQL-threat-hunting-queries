# Monitor for analytics editing in Microsoft Sentinel

# Description

The following query takes into advantage the SentinelAudit table and will allow you to monitor any editing of Analytics rules within Microsoft Sentinel.

### Microsoft Sentinel
```
SentinelAudit
| where Status == @"Success"
| where Description == @"Create or update analytics rule." or Description == @"Analytics rule deleted"
| extend User = parse_json(ExtendedProperties)["CallerName"]
| project TimeGenerated, SentinelResourceName, Description, User
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 30/06/2025    | Initial publish                        |
