# Identify endpoints running WSL without MDE plug-in

## Description

The following query will identify endpoints running Windows Subsystem for Linux (WSL) without the WSL Microsoft Defender for Endpoint plug-in.

### Microsoft Sentinel & Defender XDR
```
let WSLDevices = DeviceProcessEvents
| where ActionType has "ProcessCreated"
| where ProcessVersionInfoOriginalFileName has "wsl.exe"
| where ProcessVersionInfoFileDescription has "Windows Subsystem for Linux"
| project DeviceName;
WSLDevices
    | join kind=leftanti (DeviceTvmSoftwareInventory
    | where SoftwareName has "microsoft_defender_for_endpoint_plug-in_for_wsl"
    | project DeviceName
) on DeviceName
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 16/06/2024    | Initial publish                        |
