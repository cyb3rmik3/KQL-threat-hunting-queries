# Alerts related to Deception in Microsoft Defender XDR

## Description

The following query will identify alerts in Microsoft Sentinel, related to the Deception capability of Microsoft Defender XDR.

### Microsoft Sentinel
```
let Timeframe = 7d; // Choose proper timeframe
AlertEvidence
| where TimeGenerated > ago(Timeframe)
| mv-expand AdditionalFields
| extend AlertTags = parse_json(AdditionalFields.Tags)
| mv-expand AlertTags
| extend DeceptionTags = parse_json(AlertTags.TagName)
| where DeceptionTags == "Deception"
| project TimeGenerated, DeceptionTags, AlertId, Title, Categories, AttackTechniques, ServiceSource, DetectionSource, EntityType, EvidenceRole, DeviceId, DeviceName, LocalIP
| sort by TimeGenerated desc 
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 13/07/2024    | Initial publish                        |
