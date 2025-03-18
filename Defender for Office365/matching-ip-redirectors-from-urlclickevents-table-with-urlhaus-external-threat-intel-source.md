# Matching IP redirectors from UrlClickEvents table with URLHaus external threat intel source

## Description

The following query leverages UrlClickEvents and more specifically the UrlChain column to unfold redirectors identified from user's clicks at Emails, Teams messages and Office 365 apps, and also matches these redirector URLs to OpenPhish theat intelligence source.

### Microsoft Defender XDR
```
let URLHausOnlineRAW = externaldata (UHFeed:string) ["https://urlhaus.abuse.ch/downloads/csv_online/"] with(format="txt")
| where UHFeed !startswith "#"
| extend UHRAW=replace_string(UHFeed, '"', '')
| project splitted=split(UHRAW, ',')
| mv-expand id=splitted[0], dateadded=splitted[1], UHUrl=splitted[2], UHurl_status=splitted[3], UHlast_onlin=splitted[4], UHthreat=splitted[5], UHtags=splitted[6], UHLink=splitted[7], UHReporter=splitted[8]
| extend UHUrl = tostring(UHUrl)
| extend UHExtractedIP = extract(@'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', 0, UHUrl)
| where isnotempty(UHExtractedIP);
UrlClickEvents
| where ActionType == "ClickAllowed" // Click has been allowed by SafeLinks
| extend UrlChain = todynamic(UrlChain)
| mv-expand UrlChain
| extend UrlString = tostring(UrlChain)
| extend ExtractedIP = extract(@'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', 0, UrlString)
| where isnotempty(ExtractedIP)
| join kind=inner URLHausOnlineRAW on $left.ExtractedIP == $right.UHExtractedIP
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 18/3/2025     | Initial publish                        |
