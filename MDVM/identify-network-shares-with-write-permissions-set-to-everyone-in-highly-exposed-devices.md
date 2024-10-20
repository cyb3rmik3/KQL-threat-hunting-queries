# Identify network shares with write permissions set to Everyone in highly exposed devices

## Description

The following query leverages DeviceTvmSecureConfigurationAssessment table and specifically ConfigurationId "scid-4001" (Remove share write permission set to "Everyone"), a weakness which is available at the Microsoft Defender Vulnerability Management (MDVM) add-on license. Results provided include network shares with write permissions set to Everyone in highly exposed devices.

### Microsoft Defender XDR
```
let DevVulNetShares = DeviceTvmSecureConfigurationAssessment 
    | where ConfigurationId has "scid-4001"
    | where IsCompliant == "0"
    | where IsApplicable == "1"
    | extend Folder = parse_json(Context)[0][0]
    | extend Path = parse_json(Context)[0][1]
    | project DeviceId, DeviceName, OSPlatform, Folder, Path;
let DeviceInformation = DeviceInfo
    | where ExposureLevel has "High"
    | distinct DeviceId, ExposureLevel;
union DevVulNetShares, DeviceInformation
    | summarize by DeviceId
    | join ( DevVulNetShares ) on DeviceId
    | join kind=leftouter ( DeviceInformation ) on DeviceId
    | project DeviceId,
            DeviceName,
            OSPlatform, 
            Folder, 
            Path
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 06/10/2024    | Initial publish                        |
| 1.0           | 20/10/2024    | Description refinement                 |
