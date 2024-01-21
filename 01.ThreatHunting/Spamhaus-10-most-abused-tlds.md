# Spamhaus 10 Most Abused TLDs

### Description

The following query will hunt for inbound emails with SenderMailFromDomain and SenderFromDomain that match Spamhaus 10 Most Abused Top Level Domains.

### References
- https://www.spamhaus.org/statistics/tlds/
- https://github.com/cyb3rmik3/Hunting-Lists/

### Microsoft Defender XDR
```
let SpamhausTLD = externaldata(TLD: string)[@"https://raw.githubusercontent.com/cyb3rmik3/Hunting-Lists/main/spamhaus-abused-tlds.csv"] with (format="csv", ignoreFirstRecord=True);
let Timeframe = 1d; // Choose the best timeframe for your investigation
let SMFDEvents = EmailEvents
 | where Timestamp > ago(Timeframe)
 | where EmailDirection == "Inbound"
 | where SenderMailFromDomain has_any (SpamhausTLD)
 | project Timestamp, NetworkMessageId, SenderMailFromAddress, SenderFromAddress, SenderIPv4, RecipientEmailAddress, DeliveryAction, ThreatTypes, EmailAction, EmailActionPolicy, UserLevelAction, UserLevelPolicy, LatestDeliveryLocation, LatestDeliveryAction;
let SFDEvents = EmailEvents
 | where Timestamp > ago(Timeframe)
 | where EmailDirection == "Inbound"
 | where SenderFromDomain has_any (SpamhausTLD)
 | project Timestamp, NetworkMessageId, SenderMailFromAddress, SenderFromAddress, SenderIPv4, RecipientEmailAddress, DeliveryAction, ThreatTypes, EmailAction, EmailActionPolicy, UserLevelAction, UserLevelPolicy, LatestDeliveryLocation, LatestDeliveryAction;
 (union isfuzzy=true
     (SMFDEvents),
     (SFDEvents)
    | summarize SenderMailFromAddresses = make_set(SenderMailFromAddress), SenderFromAddresses = make_set(SenderFromAddress), TimeReceived = arg_max(Timestamp, *) by NetworkMessageId    
    | project-reorder TimeReceived, NetworkMessageId, SenderMailFromAddress, SenderFromAddress, SenderIPv4, RecipientEmailAddress, DeliveryAction, ThreatTypes, EmailAction, EmailActionPolicy, UserLevelAction, UserLevelPolicy, LatestDeliveryLocation, LatestDeliveryAction
    | sort by TimeReceived
)
```

### MITRE ATT&CK Mapping
- Tactic: Initial Access
- Technique ID: T1566
- [Phishing](https://attack.mitre.org/techniques/T1566/)

### Source

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 21/01/2024    | Initial publish                   |
