# Detect malware communication using SSL inspection

## Description

The following query will list all emails received on the Timeframe specified that haven’t been blocked and have an attachment. This could help get an overview of the email attachments recently received that might rise suspicions.

### References
- https://www.michalos.net/2023/10/03/investigating-initial-access-in-compromised-email-accounts-using-microsoft-365-defender/

### Microsoft 365 Defender
```
DeviceNetworkEvents
// Define timeframe 
| where Timestamp > ago(30d)
| where ActionType == "SslConnectionInspected"
| extend AdditionalFields = todynamic(AdditionalFields)
| extend issuer = tostring(AdditionalFields.issuer), subject = tostring(AdditionalFields.subject), direction = tostring(AdditionalFields.direction)
| where direction == "Out" and not(ipv4_is_private(RemoteIP))
// Define issuer and subject parameters
| where AdditionalFields.issuer has_any ("AsyncRAT Server", "Major Cobalt Strike" "Laplas.app") or AdditionalFields.subject has_any ("AsyncRAT Server", "Major Cobalt Strike", "Quasar Server CA", "Laplas.app", "Mythic", "DcRat", "VenomRAT", "BitRAT")
| sort by Timestamp desc 
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 03/10/2023    | Initial publish                        |
