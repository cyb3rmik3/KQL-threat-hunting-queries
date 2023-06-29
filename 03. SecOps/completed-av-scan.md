# Completed AV Scan

## Description

The following query will check for the Devices declared, when was the last Antivirus Scan completed along with the Scan Type (Quick/Full) and which user initiated it.

### Microsoft 365 Defender
```
// Definde hosts of interest
let Device = dynamic(["DeviceName1", "DeviceName2", "DeviceName3"]);
DeviceEvents
// Definde timeframe below
| where Timestamp > ago(30d)
| where DeviceName has_any (Device)
| where ActionType has "AntivirusScanCompleted"
| extend AdditionalFields = todynamic(AdditionalFields)
| extend ScanType = AdditionalFields.["ScanTypeIndex"], StartedBy= AdditionalFields.["User"]
| project Timestamp, DeviceName, ActionType, ScanType, StartedBy
| sort by Timestamp desc
```

### Microsoft Sentinel
```
// Definde hosts of interest
let Device = dynamic(["DeviceName1", "DeviceName2", "DeviceName3"]);
DeviceEvents
// Definde timeframe below
| where TimeGenerated > ago(30d)
| where DeviceName has_any (Device)
| where ActionType has "AntivirusScanCompleted"
| extend AdditionalFields = todynamic(AdditionalFields)
| extend ScanType = AdditionalFields.["ScanTypeIndex"], StartedBy= AdditionalFields.["User"]
| project Timestamp, DeviceName, ActionType, ScanType, StartedBy
| sort by Timestamp desc
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 29/06/2023    | Initial publish                        |
