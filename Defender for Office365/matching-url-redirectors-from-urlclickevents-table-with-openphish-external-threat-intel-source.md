# Matching URL redirectors from UrlClickEvents table with OpenPhish external threat intel source

## Description

The following query leverages UrlClickEvents and more specifically the UrlChain column to unfold redirectors identified from user's clicks at Emails, Teams messages and Office 365 apps, and also matches these redirector URLs to OpenPhish theat intelligence source.

### Microsoft Defender XDR
```
let OpenPhish = externaldata(Domain: string)[@"https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"] with (format="txt", ignoreFirstRecord=True);
UrlClickEvents
| extend UrlChain = todynamic(UrlChain)
| mv-expand UrlChain
//| where Url != UrlChain // You can choose to remove the initial URL if you already use another analytic
//| where ActionType == "ClickAllowed" // Click has been allowed by SafeLinks
| extend ParsedUrl = parse_url(tostring(UrlChain))
| extend ParsedUrl_Domain = parse_json(ParsedUrl)["Host"]
| extend DomainParts = split(ParsedUrl_Domain, ".")  // Split the domain into parts by "."
| extend CleanDomain = strcat_array(array_slice(DomainParts, array_length(DomainParts)-2, 2), ".")
| where CleanDomain in~ (OpenPhish)
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 18/3/2025     | Initial publish                        |
