# Identify endpoints where MitigationStatus is Isolated

## Description

The following query will leverage the DeviceInfo table and identify endpoints where MitigationStatus Isolation equals true. It will also the logged on UserName and Domain.

### Microsoft Defender XDR
```
let Timeframe = 1h; // Choose the best timeframe for your investigation
DeviceInfo
| where TimeGenerated > ago(Timeframe)
| extend DeviceUser = parse_json(LoggedOnUsers)
| mv-expand DeviceUser
| extend LoggedOnUsername = tostring(DeviceUser.UserName)
| extend LoggedOnDomainName = tostring(DeviceUser.DomainName)
| extend MitigationStatusObject = parse_json(MitigationStatus)
| mv-expand MitigationStatusObject
| extend IsolationStatus = MitigationStatusObject.Isolated
| where IsolationStatus == "true"
| distinct DeviceId, DeviceName, OSPlatform, LoggedOnUsername, LoggedOnDomainName, Isolation = "Yes"
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 27/04/2024    | Initial publish                        |
