# Uncover every prompt-injection detection and its disposition

## Description

This query helps answer with regards to prompt-injection emails, how much is MDO catching, and is any of it still reaching mailboxes rather than quarantine?

### Microsoft Defender XDR
```
// Prompt-injection detections over the last 30 days, by disposition
let lookback = 30d;
EmailEvents
| where Timestamp > ago(lookback)
| where DetectionMethods has "Prompt injection"
| summarize Messages = count() by DeliveryAction, DeliveryLocation, bin(Timestamp, 1d)
| sort by Timestamp desc

```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 08/10/2026    | Initial publish                        |
