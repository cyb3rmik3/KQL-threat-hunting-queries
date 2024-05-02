# Identify endpoints where MitigationStatus is Isolated

## Description

The following query will leverage the DeviceInfo table and identify endpoints where MitigationStatus Isolation equals true. It will also the logged on UserName and Domain.

### Microsoft Defender XDR

```
let Timeframe = 4h; // Choose the best timeframe for your investigation
DeviceInfo
| where Timestamp > ago(Timeframe)
| summarize arg_max(Timestamp, *) by DeviceId //only look at the most recent entry
| extend DeviceUser = parse_json(LoggedOnUsers)
| mv-expand DeviceUser
| extend LoggedOnUsername = tostring(DeviceUser.UserName)
| extend LoggedOnDomainName = tostring(DeviceUser.DomainName)
| extend MitigationStatusObject = parse_json(MitigationStatus)
| mv-expand MitigationStatusObject
| extend IsolationStatus = tostring(MitigationStatusObject.Isolated)
| where IsolationStatus == "true"
| project Timestamp, DeviceId, DeviceName, OSPlatform, LoggedOnUsername, LoggedOnDomainName, IsolationStatus
```

### Versioning
| Version       | Date          | Comments                                                                            |
| ------------- |---------------| ------------------------------------------------------------------------------------|
| 1.0           | 27/04/2024    | Initial publish                                                                     |
| 1.1           | 01/05/2024    | Only show Devices where the most recent entry of the Table hast the isolated status |
