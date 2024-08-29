# Identify endpoint browser extensions with “Can turnoff malware protections” permissions

## Description

The following query leverages DeviceTvmBrowserExtensions and DeviceTvmBrowserExtensionsKB tables wich are available at the Threat and Vulnerability Management (TVM) add-on license. Results provided include endpoints which have browser extensions installed with “Can turnoff malware protections” permissions.

### Microsoft Defender XDR
```
let BrowserExtMalwareProtectionKB = DeviceTvmBrowserExtensionsKB 
    | where PermissionName contains "Can turn off malware protections"
    | project ExtensionId, ExtensionName, ExtensionRisk, PermissionName;
let BrowserExtMalwareProtection = DeviceTvmBrowserExtensions
    | project ExtensionId, DeviceId;
let DeviceInformation = DeviceInfo
    | project DeviceId, DeviceName, Timestamp;
union BrowserExtMalwareProtection, BrowserExtMalwareProtectionKB,
        DeviceInformation
    | summarize by ExtensionId, DeviceId
    | join ( BrowserExtMalwareProtectionKB ) on ExtensionId
    | join kind=rightouter ( BrowserExtMalwareProtection ) on ExtensionId
    | join ( DeviceInformation ) on DeviceId
    | summarize DeviceCount=dcount(DeviceName), arg_max(Timestamp, *) by ExtensionName, ExtensionRisk
    | sort by DeviceCount asc, ExtensionRisk
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 29/08/2024    | Initial publish                        |
| 1.1           | 29/08/2024    | Refinement                        |
