# Completed AV Scan

## Description

The following query check the "last seen" field and returnd when it was last connected.

### Microsoft 365 Defender
```
// Definde hosts of interest
let Host = dynamic(["HostName1", "HostName2", "HostName3"]);
DeviceEvents
// Definde timeframe below
| where Timestamp > ago(30d)
| where ActionType has "AntivirusScanComplete"
| where DeviceName has_any (Host)
| extend AdditionalFields = todynamic(AdditionalFields)
| extend ScanType = AdditionalFields.["ScanTypeIndex"], StartedBy= AdditionalFields.["User"]
| project Timestamp, DeviceName, ActionType, ScanType, StartedBy
| sort by Timestamp desc
```

### Microsoft Sentinel
```
// Definde hosts of interest
let Host = dynamic(["HostName1", "HostName2", "HostName3"]);
DeviceEvents
// Definde timeframe below
| where TimeGenerated > ago(90d)
| where ActionType has "AntivirusScanComplete"
| where DeviceName has_any (Host)
| extend AdditionalFields = todynamic(AdditionalFields)
| extend ScanType = AdditionalFields.["ScanTypeIndex"], StartedBy= AdditionalFields.["User"]
| project Timestamp, DeviceName, ActionType, ScanType, StartedBy
| sort by Timestamp desc
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 29/06/2023    | Initial publish                        |
