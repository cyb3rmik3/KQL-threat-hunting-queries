# Endpoints accessing .zip or .mov websites

### Description

Google recently announced a series of new gTLDs available for registration amongst them, .zip and .mov. While Google saw an opportunity in providing public access to these domains, defenders are already worried that they could be used for malicious purposes. The following queries ~~might score high in precision as they will return requests for .zip and .mov files in results, however it could be a good starting point for threat hunting~~ provide high recall and focus on the domain after [βrคŞhemuŞ](https://twitter.com/8ra5hEmu5/status/1658131948290600964) tweet. Also, query provides a hunting opportunity for .zip and .mov accessed domains originating from file explorer.

### References
- https://blog.google/products/registry/8-new-top-level-domains-for-dads-grads-tech/
- https://isc.sans.edu/diary/29838
- https://twitter.com/8ra5hEmu5/status/1658131948290600964

### Microsoft 365 Defender
```
DeviceNetworkEvents
// Define the time you are interested to look into
| where Timestamp > ago(1d)
// Remove the line below in case you want to look into both successful and unsuccessful events
| where ActionType == "ConnectionSuccess"
// The line below refers to connections made when requesting a .zip through file explorer
// | where InitiatingProcessFileName == @"svchost.exe"
// Define RemoteURL
| where RemoteUrl startswith "https://" or RemoteUrl startswith "http://"
// Define domain as a string that includes a domain exclusively leaving outside .zip or .mov accessed files for download
| extend domain = tostring(extract("https?://([^:/]*)(:?)(/|$)", 1, RemoteUrl)) 
// String should exclusively look for .zip or .mov TLDs
| where domain endswith ".zip" or domain endswith ".mov"
| project Timestamp, DeviceName, ActionType, RemoteUrl
// Sort by newsest events first
| sort by Timestamp desc 
```

### Microsoft Sentinel
```
DeviceNetworkEvents
// Define the time you are interested to look into
| where TimeGenerated > ago(1d)
// Remove the line below in case you want to look into both successful and unsuccessful events
| where ActionType == "ConnectionSuccess"
// The line below refers to connections made when requesting a .zip through file explorer
// | where InitiatingProcessFileName == @"svchost.exe"
// Define RemoteURL
| where RemoteUrl startswith "https://" or RemoteUrl startswith "http://"
// Define domain as a string that includes a domain exclusively leaving outside .zip or .mov accessed files for download
| extend domain = tostring(extract("https?://([^:/]*)(:?)(/|$)", 1, RemoteUrl)) 
// String should exclusively look for .zip or .mov TLDs
| where domain endswith ".zip" or domain endswith ".mov"
| project Timestamp, DeviceName, ActionType, RemoteUrl
// Sort by newsest events first
| sort by Timestamp desc 
```

### MITRE ATT&CK Mapping
- Tactic: Execution
- Technique ID: T1204.001
- [User Execution: Malicious Link](https://attack.mitre.org/techniques/T1204/001/)

### Source
- MDE

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 14/05/2023    | Initial publish                   |
| 1.1           | 16/05/2023    | Transformed query for high recall |
