# Leveraging Spamhaus DROP list to identify delivered emails from suspicious source IPs

## Description

The following query leverages Spamhaus Don't Route Or Peer Lists (DROP) to identify delivered emails from suspicious source IPs. While most probably communications from these IP blocks will be marked as spam, using this query will uncover any delivered emails from DROP lists.
- Reference: https://www.spamhaus.org/blocklists/do-not-route-or-peer/

### Microsoft Defender XDR
```
// Define Don't Route Or Peer Lists (DROP) json file from Spamhaus
let DROPlist = externaldata(cidr: string)
    [@"https://www.spamhaus.org/drop/drop_v4.json"] 
    with (format="multijson", ignoreLastRecord=True);
// Associate EmailEvents table, with Delivered as LatestDeliveryAction
EmailEvents
| extend SenderIPv4Str = tostring(SenderIPv4)
| join kind=inner (
    DROPlist
) 
on $left.SenderIPv4Str == $right.cidr  // Join based on CIDR match
| where ipv4_is_in_range(SenderIPv4Str, cidr)
| where LatestDeliveryAction == "Delivered"
| project Timestamp, SenderIPv4Str, cidr, SenderDisplayName,
    SenderFromAddress, SenderMailFromAddress, Subject

```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 25/1/2025     | Initial publish                        |
