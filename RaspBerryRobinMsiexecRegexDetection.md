# Detect RaspBerry Robin cmd through msiexec and regex on http request call

## Query Information

### Description

Description

### References
- https://isc.sans.edu/diary/29838

### Microsoft 365 Defender
```
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where ActionType == "ConnectionSuccess"
| where RemoteUrl endswith ".zip" or RemoteUrl endswith ".mov"
| project Timestamp, DeviceName, ActionType, RemoteUrl
```

### Microsoft Sentinel
```
DeviceNetworkEvents
| where TimeGenerated > ago(1d)
| where ActionType == "ConnectionSuccess"
| where RemoteUrl endswith ".zip" or RemoteUrl endswith ".mov"
| project Timestamp, DeviceName, ActionType, RemoteUrl
```

### MITRE ATT&CK Mapping

###### T1204.001
[https://attack.mitre.org/techniques/T1204/001/](User Execution: Malicious Link)
