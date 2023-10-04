# Review recently received emails with phishing related subject keywords

## Description

The following query will go through a set of keywords included in a curated list that could be found in email’s subject, that could potentially be correlated to phishing emails. This query will most probably return a lot of false/positives, however it could potentially return results significant enough to go through.

### References
- https://www.michalos.net/2023/10/03/investigating-initial-access-in-compromised-email-accounts-using-microsoft-365-defender/

### Microsoft 365 Defender
```
let CompromizedEmailAddress = ""; // Insert the email address of the compromised email address
let SuspiciousKeywords = externaldata(Keywords: string)[@"https://raw.githubusercontent.com/cyb3rmik3/Hunting-Lists/main/phishing-keywords.csv"] with (format="csv", ignoreFirstRecord=True);
let Timeframe = 2d; // Choose the best timeframe for your investigation
EmailEvents 
    | where RecipientEmailAddress == CompromizedEmailAddress
    | where Timestamp > ago(Timeframe)
    | where Subject has_any (SuspiciousKeywords)
    | where DeliveryAction == "Delivered"
    | project Timestamp, SenderMailFromAddress, SenderFromAddress, SenderDisplayName, SenderMailFromDomain, SenderFromDomain, SenderIPv4, AttachmentCount, UrlCount, LatestDeliveryAction
    | sort by Timestamp desc 
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 04/10/2023    | Initial publish                        |
