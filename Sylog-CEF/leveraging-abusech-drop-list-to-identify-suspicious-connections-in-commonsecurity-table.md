# Leveraging abuse.ch DROP list to identify suspicious connections in CommonSecurityLog table

## Description

The following query leverages abuse.ch Don't Route Or Peer Lists (DROP) to identify suspicious connections in CommonSecurityLog table. Based on the security controls onboarded your Unified Security Operations, this will allow to search for suspicious connections accross your estate.
- Reference: https://www.spamhaus.org/blocklists/do-not-route-or-peer/

### Microsoft Defender XDR
```
let DROPlist = externaldata(cidr: string)
    [@"https://www.spamhaus.org/drop/drop_v4.json"] 
    with (format="multijson", ignoreLastRecord=True);
CommonSecurityLog
| where not(
    DestinationIP startswith "10." or
    DestinationIP startswith "172." and toint(split(DestinationIP, ".")[1]) between (16 .. 31) or
    DestinationIP startswith "192.168."
)
| extend DestinationIPAddr = tostring(DestinationIP)
| join kind=inner (
    DROPlist
) 
on $left.DestinationIPAddr == $right.cidr  // Join based on CIDR match
| where ipv4_is_in_range(DestinationIPAddr, cidr)
| project TimeGenerated, DestinationIPAddr, cidr
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 25/1/2025     | Initial publish                        |
