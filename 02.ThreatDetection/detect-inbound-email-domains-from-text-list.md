# Detect inbound email domains from text list

## Description

Following a challenging request from a fellow Microsoft Tech Community member, the query below will help you detect inbound emails which match the domains provided from a public text file. It also allows to exclude specific domains, if required.

### References
- https://techcommunity.microsoft.com/t5/microsoft-defender-xdr/365-advance-hunting/m-p/3937681

### Microsoft 365 Defender
```
let domainList = externaldata(domain: string) [@"https://raw.githubusercontent.com/tsirolnik/spam-domains-list/master/spamdomains.txt"] with (format="txt"); // Change the text file to whatever you want
let excludedDomains = datatable(excludeddomain :string)  // Add as many domains you would like to exclude
 ["domain1.tld",
  "domain2.tld",
  "domain3.tld"];   
let Timeframe = 1d; // Choose the best timeframe for your investigation
let SuspiciousEmails = EmailEvents
    | where Timestamp > ago(Timeframe)
    | where EmailDirection == "Inbound"
    | extend EmailDomain = tostring(split(SenderMailFromAddress, '@')[1])
    | join kind=inner (domainList) on $left.EmailDomain == $right.domain
    | where not(EmailDomain in (['excludedDomains']))
    | project Timestamp, NetworkMessageId, SenderMailFromAddress, SenderFromAddress, SenderDisplayName, RecipientEmailAddress, EmailDomain, domain, Subject, LatestDeliveryAction;
SuspiciousEmails
    | join (EmailEvents
    | project NetworkMessageId
)on NetworkMessageId
    | sort by Timestamp desc
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 17/11/2023    | Initial publish                        |




