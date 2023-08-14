# Remcos RAT checking for geolocation through web

### Description

SANS ISC published a diary on 30/05/2023 where ModiLoader installs a Remcos RAT payload which checks for geolocation through web by geoplugin[.]net. The following query checks whether an attempt to connect to geoplugin[.]net has been made by a non-browser application. Query can be modified based on your environment and the browsers used, also other geolocation services could be checked.

### References
- https://isc.sans.edu/diary/29896

### Microsoft 365 Defender
```
// Define browser executable filenames
let Browser = dynamic(["firefox.exe", "msedge.exe", "chrome.exe", "opera.exe", "brave.exe"]);
DeviceNetworkEvents
// Define timeframe 
| where Timestamp > ago(30d)
| where not(InitiatingProcessFileName in (['Browser']))
// Define service used to locate geographical information
| where RemoteUrl contains 'geoplugin.net'
| project Timestamp, DeviceName, LocalIP, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessAccountUpn
| sort by Timestamp desc
```

### Microsoft Sentinel
```
// Define browser executable filenames
let Browser = dynamic(["firefox.exe", "msedge.exe", "chrome.exe", "opera.exe", "brave.exe"]);
DeviceNetworkEvents
// Define timeframe 
| where TimeGenerated > ago(30d)
| where not(InitiatingProcessFileName in (['Browser']))
// Define service used to locate geographical information
| where RemoteUrl contains 'geoplugin.net'
| project Timestamp, DeviceName, LocalIP, RemoteUrl, RemoteIP, RemotePort, InitiatingProcessFileName, InitiatingProcessAccountUpn
| sort by Timestamp desc
```

### MITRE ATT&CK Mapping
- Tactic: Discovery
- Technique ID: T1614
- [System Location Discovery](https://attack.mitre.org/techniques/T1614/)

### Source

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 08/06/2023    | Initial publish                   |
