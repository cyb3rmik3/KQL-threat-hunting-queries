# Crowdstrike suspicious domains

### Description

Following Crowdstrike incident that paralyzed IT systems throughout the world, threat actors commenced phishing attacks towards organizations impersonating Crowdstrike support. The following query will take into account a curated hutning list from publick reports, looking for suspicious domains.

### References
- https://www.pcmag.com/news/dont-fall-for-it-hackers-pounce-on-crowdstrike-outage-with-phishing-emails

### Microsoft XDR & Microsoft Sentinel

#### EmailUrlInfo
```
let ThreatIntelFeed = externaldata(Domain: string)[@"https://raw.githubusercontent.com/cyb3rmik3/Hunting-Lists/main/crowdstrike-phishing-domains.csv"] with (format="csv", ignoreFirstRecord=True)
| project Domain = tolower(Domain);
EmailUrlInfo
| join kind=inner ThreatIntelFeed on $left.Url == $right.Domain
| join EmailEvents on NetworkMessageId
```
#### EmailEvents
```
let ThreatIntelFeed = externaldata(Domain: string)[@"https://raw.githubusercontent.com/cyb3rmik3/Hunting-Lists/main/crowdstrike-phishing-domains.csv"] with (format="csv", ignoreFirstRecord=True)
| project Domain = tolower(Domain);
EmailEvents
| join kind=inner ThreatIntelFeed on $left.SenderMailFromDomain == $right.Domain
| join EmailEvents on NetworkMessageId
```


### MITRE ATT&CK Mapping
- Tactic: Initial Access
- Technique ID: T1566
- [Phishing](https://attack.mitre.org/techniques/T1566/)

### Source

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 20/07/2024    | Initial publish                   |
