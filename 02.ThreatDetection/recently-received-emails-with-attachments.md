# Review recently received emails with attachments

## Description

The following query will list all emails received on the Timeframe specified that haven’t been blocked and have an attachment. This could help get an overview of the email attachments recently received that might rise suspicions.

### References
- https://www.michalos.net/2023/10/03/investigating-initial-access-in-compromised-email-accounts-using-microsoft-365-defender/

### Microsoft 365 Defender
```
let CompromizedEmailAddress = ""; // Insert the email address of the compromised email address
let Timeframe = 2d; // Choose the best timeframe for your investigation
let EmailInformation = EmailEvents
    | where RecipientEmailAddress == CompromizedEmailAddress
    | where Timestamp > ago(Timeframe)
    | where DeliveryAction != "Blocked"
    | where AttachmentCount != "0"
    | project Timestamp, NetworkMessageId, SenderMailFromAddress, SenderFromAddress, SenderDisplayName, ThreatNames;
EmailInformation
    | join (EmailAttachmentInfo
    | project NetworkMessageId, FileName, FileType, FileSize
) on NetworkMessageId
| sort by Timestamp desc
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 03/10/2023    | Initial publish                        |
