# Endpoints accessing .zip or .mov websites

### Description

Google recently announced a series of new gTLDs available for registration amongst them, .zip and .mov. While Google saw an opportunity in providing public access to these domains, defenders are already worried that they could be used for malicious pruposes. The following queries might score high in precision as they will return requests for .zip and .mov files in resutls, however it could be a good starting point for threat hunting. Also, query provides a hunting opportunity for .zip and .mov accessed domains originating from file explorer.

### References
- https://blog.google/products/registry/8-new-top-level-domains-for-dads-grads-tech/
- https://isc.sans.edu/diary/29838

### Microsoft 365 Defender
```
DeviceNetworkEvents
// Define the time you are interested to look into
| where Timestamp > ago(1d)
// Remove the line below in case you want to look into both successful and unsuccessful events
| where ActionType == "ConnectionSuccess"
// The line below refers to connections made when requestion a .zip through file explorer
// | where InitiatingProcessFileName == @"svchost.exe"
| where RemoteUrl endswith ".zip" or RemoteUrl endswith ".mov"
| project Timestamp, DeviceName, ActionType, RemoteUrl
```

### Microsoft Sentinel
```
DeviceNetworkEvents
// Define the time you are interested to look into
| where TimeGenerated > ago(1d)
// Remove the line below in case you want to look into both successful and unsuccessful events
| where ActionType == "ConnectionSuccess"
// The line below refers to connections made when requestion a .zip through file explorer
// | where RemoteUrl endswith ".zip" or RemoteUrl endswith ".mov"
| project Timestamp, DeviceName, ActionType, RemoteUrl
```

### MITRE ATT&CK Mapping
- Technique ID: T1204.001
- [User Execution: Malicious Link](https://attack.mitre.org/techniques/T1204/001/)
