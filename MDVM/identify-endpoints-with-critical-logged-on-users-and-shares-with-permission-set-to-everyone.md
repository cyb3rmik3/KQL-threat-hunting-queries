# Identify endpoints with critical logged on users, and shares with permission set to “Everyone”

## Description

The following query leverages DeviceTvmSecureConfigurationAssessment table which is available at the MDVM add-on license. Results provided include endpoints where users marked as critical log in, and the associated endpoints have shares with permission set to "Everyone".

### Microsoft Defender XDR
```
let CriticalUsers = IdentityInfo 
    | where CriticalityLevel == "1"
    | project AccountName, AccountDisplayName
    | join kind=inner (DeviceInfo
    | extend AccountNameDev = parse_json(LoggedOnUsers)[0]["UserName"]
    | extend AccountNameDevice = tostring(AccountNameDev)
    | where isnotempty(AccountNameDevice)
    | project DeviceId, DeviceName, AccountNameDevice)
    on $left.AccountName == $right.AccountNameDevice
    | summarize by DeviceId, DeviceName, AccountName, AccountDisplayName;
DeviceTvmSecureConfigurationAssessment 
    | where ConfigurationId has "scid-4001"
    | where IsCompliant == "0"
    | where IsApplicable == "1"
    | extend Folder = parse_json(Context)[0][0]
    | extend Path = parse_json(Context)[0][1]
    | project DeviceId, DeviceName, OSPlatform, Folder, Path
    | join kind=inner CriticalUsers on $left.DeviceId == $right.DeviceId
    | project DeviceId, DeviceName, OSPlatform,
        Folder, Path, AccountName, AccountDisplayName
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 12/02/2025     | Initial publish                        |
