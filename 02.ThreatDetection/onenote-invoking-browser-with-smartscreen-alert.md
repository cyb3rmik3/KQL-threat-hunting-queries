# OneNote invoking browser that produced smart screen warning

## Description

A detection rule for OneNote files, invoking browser (inline URL) which produced a smart screen URL warning. Detection has been provided following public discussion with @DhaeyerWolf.

### Microsoft 365 Defender & Microsoft Sentinel
```
DeviceInfo
let Process = DeviceProcessEvents
| where InitiatingProcessFileName contains "onenote.exe"
// Define any other browser files below that may be present in your environment
| where FileName has_any ("firefox.exe","msedge.exe","chrome.exe")
| project Timestamp, DeviceId, DeviceName, AccountDomain, AccountName;
// Joining DeviceEvents table to correlate SmartScreen URL warnings
Process
| join (DeviceEvents
| where ActionType == "SmartScreenUrlWarning"
| project DeviceId, DeviceName, InitiatingProcessAccountUpn, RemoteUrl
) on DeviceId
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 28/02/2022    | Initial publish                        |
| 1.1           | 23/05/2023    | Transformed to template, minor changes |

