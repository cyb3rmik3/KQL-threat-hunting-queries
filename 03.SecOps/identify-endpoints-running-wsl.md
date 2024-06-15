# Identify endpoints that run WSL

## Description

The following query will identify endpoints running Windows Subsystem for Linux (WSL).

### Microsoft Sentinel & Defender XDR
```
DeviceProcessEvents
| where ActionType has "ProcessCreated"
| where ProcessVersionInfoOriginalFileName has "wsl.exe"
| where ProcessVersionInfoFileDescription has "Windows Subsystem for Linux"
| summarize by DeviceName
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 15/06/2024    | Initial publish                        |
