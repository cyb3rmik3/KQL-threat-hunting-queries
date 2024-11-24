# Get to know your MISP threat intelligence feed

## Description

If you are aggregating a MISP instance for your threat intelligence feed in Microsoft Sentinel (or Unified SecOps, then your ThreatIntelligenceIndicator table will be able to provide some fruitful numbers on how your MISP is overall cotnributing. The following queries will allow you an overall better understanding of your MISP feed.

### Microsoft Sentinel
```
// Piechart of MISP IoCs by Threat Type
ThreatIntelligenceIndicator
| where isnotempty(TimeGenerated) and SourceSystem == 'MISP'
| summarize count() by ThreatType
| render piechart with(title="MISP IoCs by Threat Type")

// Piechart of MISP IoCs by TLP
ThreatIntelligenceIndicator
| where isnotempty(TimeGenerated) and SourceSystem == 'MISP'
| summarize count() by TrafficLightProtocolLevel
| render piechart with(title="MISP IoCs by Traffic Light Protocol Level")

// Count of ingested IoCs over a period of time
ThreatIntelligenceIndicator
| where isnotempty(TimeGenerated) and SourceSystem == 'MISP'
| where TimeGenerated between (datetime(2024-01-01) .. datetime(2024-11-30)) 
| summarize IoCsCount=count_distinct(IndicatorId) by bin(TimeGenerated, 7d)
| render timechart

// A barchart of count of Tags
ThreatIntelligenceIndicator
| where isnotempty(TimeGenerated) and SourceSystem == 'MISP'
| mv-expand todynamic(Tags)
| summarize count() by tostring(Tags)
| render barchart
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 25/11/2024    | Initial publish                        |
