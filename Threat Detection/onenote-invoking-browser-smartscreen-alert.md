// A detection rule for OneNote files, invoking a browser (inline URL) which produced a smart screen URL warning
// Defining OneNote invoking a browser
let Process = DeviceProcessEvents
| where InitiatingProcessFileName contains "onenote.exe"
| where FileName has_any ("firefox.exe","msedge.exe","chrome.exe")
| project Timestamp, DeviceId, DeviceName, AccountDomain, AccountName;
// Joining DeviceEvents table to correlate SmartScreen URL warnings
Process
| join (DeviceEvents
| where ActionType == "SmartScreenUrlWarning"
| project DeviceId, DeviceName, InitiatingProcessAccountUpn, RemoteUrl
) on DeviceId

// Provided following @DhaeyerWolf blog on MDE missing OneNote inline URLs
