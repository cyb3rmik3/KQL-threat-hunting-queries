# Matching IP redirectors from UrlClickEvents table with URLHaus external threat intel source

## Description

The following query leverages UrlClickEvents and more specifically the UrlChain column to unfold redirectors identified from user's clicks at Emails, Teams messages and Office 365 apps, and matches the IP-hosted redirector URLs against the URLhaus (abuse.ch) online malware URL threat intelligence feed.

### Prerequisites
URLhaus downloads require a free Auth-Key from the [abuse.ch Authentication Portal](https://auth.abuse.ch/). Replace `<YOUR-AUTH-KEY>` in the query with your own key and do not publish or share it. Review the [URLhaus terms of use](https://urlhaus.abuse.ch/api/), especially for commercial use.

### Microsoft Defender XDR
```
let HostIP = @'^(?:[A-Za-z][A-Za-z0-9+.-]*://)?(?:[^@/?#]*@)?(\d{1,3}(?:\.\d{1,3}){3})(?:[:/?#]|$)'; // IP address used as the URL host
let URLhausOnline = externaldata (Line:string)
    [h@"https://urlhaus-api.abuse.ch/v2/files/exports/<YOUR-AUTH-KEY>/online.csv"] with (format="txt")
| where Line !startswith "#"
| extend f = parse_csv(Line)
| extend UHUrl = tostring(f[2]), UHThreat = tostring(f[5]), UHTags = tostring(f[6]), UHLink = tostring(f[7])
| extend IP = extract(HostIP, 1, UHUrl)
| where isnotempty(IP)
| summarize UHUrls = make_set(UHUrl, 20), UHThreats = make_set(UHThreat), UHTagSets = make_set(UHTags, 20), UHLinks = make_set(UHLink, 20) by IP;
UrlClickEvents
| where ActionType == "ClickAllowed" // Click has been allowed by SafeLinks
| mv-expand Url_ = todynamic(UrlChain)
| extend UrlString = tostring(Url_)
| extend IP = extract(HostIP, 1, UrlString)
| where isnotempty(IP)
| join kind=inner URLhausOnline on IP
| project-away IP1, Url_
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 18/3/2025     | Initial publish                        |
| 1.1           | 28/11/2026    | Keyed URLhaus export, CSV-aware parsing, host-only IP matching |
