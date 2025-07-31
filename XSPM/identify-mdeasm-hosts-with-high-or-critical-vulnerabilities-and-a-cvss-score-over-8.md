# Identify hosts with High or Critical vulnerabilities and a CVSS score over 8

## Description

The following query will uncover hosts that are available from Microsoft Defender External Attack Surface Management with High or Critical vulnerabilities and a CVSS score over 8 in the Advanced Hunting tables from Exposure Management.

### References
- https://www.michalos.net/2025/07/31/breaking-down-the-microsoft-defender-external-attack-surface-management-opportunities-for-queries-in-advanced-hunting-log-analytics-workspace/

### Microsoft Defender XDR
```
ExposureGraphNodes
| where NodeLabel == @"dns-host"
| extend GraphNodeProperties = parse_json(NodeProperties)
| where GraphNodeProperties["rawData"]["highRiskVulnerabilityInsights"]["hasHighOrCritical"] == "true"
| where toreal(GraphNodeProperties["rawData"]["highRiskVulnerabilityInsights"]["maxCvssScore"]) > 8
| extend CVSSScore = parse_json(NodeProperties)["rawData"]["highRiskVulnerabilityInsights"]["vulnerableToRemoteCodeExecution"]["maxCvssScore"]
| project NodeId, Host=NodeName, CVSSScore
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 31/07/2025    | Initial publish                        |
