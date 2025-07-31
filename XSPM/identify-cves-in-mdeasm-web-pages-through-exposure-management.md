# Identify CVEs in MDEASM web pages through Exposure Management

## Description

The following query will help identify CVEs associated with web pages from MDEASM in the Advanced Hunting tables from Exposure Management.

### References
- https://www.michalos.net/2025/07/31/breaking-down-the-microsoft-defender-external-attack-surface-management-opportunities-for-queries-in-advanced-hunting-log-analytics-workspace/

### Microsoft Defender XDR
```
let WebPages = ExposureGraphNodes
| where NodeLabel == "web-page"
| project NodeId, NodeName;
WebPages
| join kind=inner (
    ExposureGraphEdges
    | where EdgeLabel == "affecting"
    | where SourceNodeLabel == "Cve"
    | project SourceNodeId, TargetNodeId, SourceNodeName
) on $left.NodeId == $right.TargetNodeId
| project Node=TargetNodeId, NodeName, VulnerabilityCVE=SourceNodeName
| order by NodeName
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 31/07/2025    | Initial publish                        |
