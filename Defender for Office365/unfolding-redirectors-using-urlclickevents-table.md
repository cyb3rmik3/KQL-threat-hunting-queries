# Unfolding redirectors using UrlClickEvents table

## Description

The following query leverages UrlClickEvents and more specifically the UrlChain column to unfold redirectors identified from user's clicks at Emails, Teams messages and Office 365 apps.

### Microsoft Defender XDR
```
UrlClickEvents
//| where ActionType == "ClickAllowed" // Uncomment if you need to filter by "ClickAllowed"
| extend UrlChain = todynamic(UrlChain)
| mv-expand UrlChain
| where Url != UrlChain
| extend UrlString = tostring(UrlChain)
| summarize Count = count() by NetworkMessageId
| where Count > 1
| join kind=inner (
    UrlClickEvents
    | extend UrlChain = todynamic(UrlChain)
    | mv-expand UrlChain
//  | where Url != UrlChain
    | extend UrlString = tostring(UrlChain)
) on NetworkMessageId
| sort by TimeGenerated asc
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 18/3/2025     | Initial publish                        |
