# Delivered mail carrying exfiltration-style URLs

## Description

This query joins delivered messages to their URLs and flags long, encoded-looking query parameters or collector-style paths, the shape an AI assistant would be instructed to call. 
- Note on field values: the exact DetectionMethods string can vary by tenant and evolve over time (in my data it appeared as {"Phish":["Prompt Injection..."]}). Confirm the literal in your own EmailEvents before operationalizing an alert, and treat this query's regex as a starting heuristic to tune against your legitimate URL patterns to keep false positives down. Always consider reviewing [https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailevents-table](Advanced Hunting schema).

### Microsoft Defender XDR
```
let lookback = 30d;
EmailEvents
| where Timestamp > ago(lookback)
| where DeliveryAction == "Delivered"
| join kind=inner (
    EmailUrlInfo
    | where Timestamp > ago(lookback)
) on NetworkMessageId
| where Url matches regex @"(?i)([?&](data|q|payload|d)=[A-Za-z0-9+/]{24,}={0,2}|/(collect|exfil|log)\b)"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, Url, DeliveryLocation
| sort by Timestamp desc

```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 08/10/2026    | Initial publish                        |
