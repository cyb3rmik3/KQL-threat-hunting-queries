# Delivered emails identified as suspicious

## Description

The following query will present email details that have been identified as suspicious after delivery.

### References
- https://www.michalos.net/2023/10/03/investigating-initial-access-in-compromised-email-accounts-using-microsoft-365-defender/

### Microsoft 365 Defender
```
let CompromizedEmailAddress = ""; // Insert the email address of the compromised email address
let Timeframe = 2d; // Choose the best timeframe for your investigation
let EmailInformation = EmailEvents
    | where RecipientEmailAddress == CompromizedEmailAddress
    | where DeliveryAction != "Blocked"
    | project Timestamp, NetworkMessageId, SenderMailFromAddress, SenderFromAddress, SenderDisplayName, ThreatNames;
EmailInformation
    | join (EmailPostDeliveryEvents 
    | where ThreatTypes != ""
    | project Timestamp, NetworkMessageId, Action, ActionType, ActionTrigger, ActionResult, DeliveryLocation, ThreatTypes, DetectionMethods
) on NetworkMessageId
| sort by Timestamp desc 
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 03/10/2023    | Initial publish                        |
