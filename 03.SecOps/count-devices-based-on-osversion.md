# Count devices based on OS version information

## Description

The following queries counts the devices onboard MDE based on the OS version information.

### Microsoft 365 Defender
```
DeviceInfo
// Define timerange below
| where Timestamp > ago(90d)
| summarize arg_max(Timestamp, *) by DeviceName
| summarize DeviceCount = dcount(DeviceName) by OSVersionInfo
| sort by DeviceCount asc 
```
### Microsoft Sentinel
```
DeviceInfo
// Define timerange below
| where TimeGenerated > ago(90d)
| summarize arg_max(Timestamp, *) by DeviceName
| summarize DeviceCount = dcount(DeviceName) by OSVersionInfo
| sort by DeviceCount asc 
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 26/07/2022    | Initial publish                        |
| 1.1           | 20/05/2023    | Transformed to template, minor changes |

