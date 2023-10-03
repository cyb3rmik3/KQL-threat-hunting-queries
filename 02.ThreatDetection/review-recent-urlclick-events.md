# Review recent UrlClick events

## Description

The following query will help identify emails with URLs inline, where the user took action and clicked any of them and the URL wasn’t blocked.

### References
- https://www.michalos.net/2023/10/03/investigating-initial-access-in-compromised-email-accounts-using-microsoft-365-defender/

### Microsoft 365 Defender
```
let CompromizedEmailAddress = ""; // Insert the email address of the compromised email address
let Timeframe = 2d; // Choose the best timeframe for your investigation
let EmailInformation = EmailEvents
    | where RecipientEmailAddress == CompromizedEmailAddress
    | where Timestamp > ago(Timeframe)
    | where UrlCount != "0"
    | project Timestamp, NetworkMessageId, SenderMailFromAddress, SenderFromAddress, SenderDisplayName, ThreatNames;
EmailInformation
    | join (UrlClickEvents
    | where ActionType != "ClickBlocked"
    | where Workload == "Email"
    | project Timestamp, Url, IPAddress, NetworkMessageId
) on NetworkMessageId
| sort by Timestamp desc 
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 03/10/2023    | Initial publish                        |
