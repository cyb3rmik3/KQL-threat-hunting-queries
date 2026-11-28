# Matching domain redirectors from UrlClickEvents table with NetAPI external threat intel source

## Description

The following query leverages UrlClickEvents and more specifically the UrlChain column to unfold redirectors identified from user's clicks at Emails, Teams messages and Office 365 apps, and matches the host of each redirector URL, as well as its parent domains, against the [NetAPI](https://netapi.com/) list of compromised domains.

### Notes
- The feed is a third-party list provided by NetAPI under CC BY 4.0. No key is required.
- Treat matches as leads to validate. The list may include domains associated with phishing only through shared infrastructure, and parent-domain matching widens the scope of a listed entry.
- Query proposed by [@slavaolesik](https://github.com/slavaolesik), who runs NetAPI, in [issue #6](https://github.com/cyb3rmik3/KQL-threat-hunting-queries/issues/6). The host extraction pattern has been adjusted so that an `@` in the query string or fragment is not read as the end of user information.

### Microsoft Defender XDR
```
let NetAPIDomains = externaldata (Domain:string) ["https://netapi.com/api2/netapi-compromised-domains.txt"] with (format="txt")
| where isnotempty(Domain) and Domain !startswith "#"
| distinct Domain;
UrlClickEvents
| where ActionType == "ClickAllowed" // Click has been allowed by SafeLinks
| extend UrlChain = todynamic(UrlChain)
| mv-expand UrlChain
| extend UrlString = tostring(UrlChain)
| extend Host = tolower(extract(@"^(?:[A-Za-z][A-Za-z0-9+.-]*://)?(?:[^@/?#]*@)?([^/:?#\s]+)", 1, UrlString))
| where isnotempty(Host)
| extend Labels = split(Host, ".")
| mv-expand Start = range(0, array_length(Labels) - 2) to typeof(int) // the host and each parent domain
| extend Domain = strcat_array(array_slice(Labels, Start, -1), ".")
| join kind=inner NetAPIDomains on Domain
| project-away Domain1
| summarize arg_min(Start, *) by ReportId, UrlString // one row per URL, the longest listed match
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 28/11/2026    | Initial publish                        |
