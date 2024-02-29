# Identify endpoints removed from isolation

## Description

The following query will return endpoints which have been removed from isolation by looking into relevant registry modifications.

### Microsoft Defender XDR
```
DeviceRegistryEvents
| where ActionType == "RegistryValueDeleted"
| where PreviousRegistryKey == @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Advanced Threat Protection"
| where RegistryValueType == "None"
| where PreviousRegistryValueData == "1"
| where PreviousRegistryValueName == "DisableEnterpriseAuthProxyValueToRestoreAfterIsolation"
| project Timestamp, DeviceId, DeviceName
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 24/02/2024    | Initial publish                        |
| 1.1           | 29/02/2024    | Change contain to isolate, thanks to Alex Verboon |
