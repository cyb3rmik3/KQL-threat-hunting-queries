# Device last seen

## Description

The following query check the "last seen" field and returnd when it was last connected.

### Microsoft 365 Defender & Microsoft Sentinel
```
DeviceInfo
| where DeviceName has "[insert devicename here]"
| extend LastSeen = Timestamp
| where Timestamp >= ago(1h)
| summarize LastSeen = arg_max(Timestamp, *) by DeviceId
| project LastSeen, DeviceId, DeviceName
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 28/02/2022    | Initial publish                        |
| 1.1           | 23/05/2023    | Transformed to template, minor changes |

