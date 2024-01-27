# Detect inbound email domains from text list

## Description

Recent rise of Remote Monitoring and Management (RMM) tools used by prominent Threat Actors for lateral movement and command and control (C2) has led to significantly getting worried about the use of legitimate software such as Teamviewer, NetSupport Manager etc. The following query has been crafted to utilize the ProcessVersionInfoCompanyName table with a hunting list created by installing and testing corresponding tools.

### References
- https://www.michalos.net/2023/11/27/detecting-rmm-tools-using-microsoft-defender-for-endpoint/

### Microsoft 365 Defender & Microsoft Sentinel
```
let RMMSoftware = externaldata(RMMSoftware: string)[@"https://raw.githubusercontent.com/cyb3rmik3/Hunting-Lists/main/rmm-software.csv"] with (format="csv", ignoreFirstRecord=True);
let ExclDevices = datatable(excludeddev :string)  // Add as many devices you would like to exclude
 ["DeviceName1",
  "DeviceName2",
  "DeviceName3"];
let Timeframe = 7d; // Choose the best timeframe for your investigation
DeviceProcessEvents
    | where Timestamp > ago(Timeframe)
    | where ProcessVersionInfoCompanyName has_any (RMMSoftware)
    | where not(DeviceName in (['ExclDevices']))
    | project Timestamp, DeviceName, ActionType, FileName, FolderPath, ProcessVersionInfoCompanyName, ProcessVersionInfoProductName, ProcessCommandLine, AccountName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
    | sort by Timestamp desc
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 27/11/2023    | Initial publish                        |




