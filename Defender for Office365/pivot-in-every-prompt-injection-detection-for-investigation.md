# Pivot in every prompt-injection detection for investigation

## Description

This query helps investigate further, once you've run (https://github.com/cyb3rmik3/KQL-threat-hunting-queries/blob/main/Defender%20for%20Office365/uncover-every-prompt-injection-detection-and-its-disposition.md)[Uncover every prompt-injection detection and its disposition].

### Microsoft Defender XDR
```
// Prompt-injection detections over the last 30 days, including details
let lookback = 30d;
EmailEvents
| where Timestamp > ago(lookback)
| where DetectionMethods has "Prompt injection"
| project Timestamp, NetworkMessageId, SenderFromAddress, RecipientEmailAddress,
          Subject, DeliveryAction, DeliveryLocation, DetectionMethods
| sort by Timestamp desc

```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 08/10/2026    | Initial publish                        |
