# Identify endpoints associated with multiple DeviceIds

## Description

There are cases where devices might be formatted and get the same hostname as before, MDE will keep both devices in Security Center, however the depreciated machine's logs will be kept for 6 months. This query will help identify endpoint hostnames associated with multiple DeviceIds.

## References
- https://learn.microsoft.com/en-us/microsoft-365/security/defender-business/mdb-offboard-devices?view=o365-worldwide&tabs=Windows1011

### Microsoft 365 Defender
```
DeviceInfo
// Definde timeframe below
| where Timestamp > ago(90d)
| where isnotempty(DeviceId)
| summarize DeviceCount = dcount(DeviceId) by DeviceName
| where DeviceCount > 1
| project DeviceName, DeviceCount
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 25/05/2023    | Initial publish                        |
| 1.1           | 14/09/2023    | Changes based on @Marshyp comments     |
