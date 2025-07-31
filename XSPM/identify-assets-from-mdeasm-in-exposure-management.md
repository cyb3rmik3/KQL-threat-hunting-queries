# Identify assets from MDEASM in Exposure Management

## Description

The following query will help identify which assets are available from Microsoft Defender External Attack Surface Management in the Advanced Hunting tables from Exposure Management.

### References
- https://www.michalos.net/2025/07/31/breaking-down-the-microsoft-defender-external-attack-surface-management-opportunities-for-queries-in-advanced-hunting-log-analytics-workspace/

### Microsoft Defender XDR
```
ExposureGraphNodes
| extend deepLinkInfo = parse_json(NodeProperties)["rawData"]["deepLink"]
| where deepLinkInfo startswith "https://portal.azure.com/#view/Microsoft_Azure_EASM/"
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 31/07/2025    | Initial publish                        |
