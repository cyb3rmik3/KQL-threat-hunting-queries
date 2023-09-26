# Detect lumma stealer using TeslaBrowser user agent

## Description

Recently seen in the wild rising further, Lumma stealer has been observed to perform HTTP GET method, while using “TeslaBrowser/5.5” user agent.

### References
- https://app.any.run/tasks/7e7728b7-9fa6-4978-99f9-b5789aa31a0a/
- https://darktrace.com/blog/the-rise-of-the-lumma-info-stealer

### Microsoft 365 Defender & Microsoft Sentinel
```
DeviceNetworkEvents
| where ActionType == "HttpConnectionInspected"
| extend json = todynamic(AdditionalFields)
| extend direction = tostring(json.direction), method = tostring(json.method), user_agent = tostring(json.user_agent)
 | where direction == "Out"
 | where method == "GET"
 | where user_agent contains @"TeslaBrowser"
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl
| sort by Timestamp desc 
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 26/09/2023    | Initial publish                        |
