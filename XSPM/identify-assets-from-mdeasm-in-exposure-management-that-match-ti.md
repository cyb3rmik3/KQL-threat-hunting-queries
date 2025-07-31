# Identify assets from MDEASM in Exposure Management that match TI

## Description

The following query will help identify which IPs from Microsoft Defender External Attack Surface Management in the Advanced Hunting tables from Exposure Management match Threat Intelligence indicators and the ThreatIntelligenceIndicator table.

### References
- https://www.michalos.net/2025/07/31/breaking-down-the-microsoft-defender-external-attack-surface-management-opportunities-for-queries-in-advanced-hunting-log-analytics-workspace/

### Microsoft Defender XDR
```
let TIIPs = 
    ThreatIntelligenceIndicator
    | extend TIIPAddress = tostring(NetworkIP)
    | where isnotempty(TIIPAddress)
    | project TIIPAddress, ThreatType, Description, ConfidenceScore;
let EASMIPs = 
    ExposureGraphNodes
    | where NodeLabel == "IP address"
    | project EASPIPAdress = tostring(NodeName);
TIIPs
| join kind=inner (
    EASMIPs
) on $left.TIIPAddress == $right.EASPIPAdress
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 31/07/2025    | Initial publish                        |
