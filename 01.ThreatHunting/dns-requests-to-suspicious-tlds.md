# DNS requests to suspicious TLDs

### Description

Zeek network layer signals for MDE includes the DnsConnectionInspected table which provides fruitful information about DNS connections. By taking into account netcraft's top 20 TLDs that are being used for cybercrime, you can hunt for suspicious DNS requests.

### References
- https://trends.netcraft.com/cybercrime/tlds
- https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/enrich-your-advanced-hunting-experience-using-network-layer/ba-p/3794693

### Microsoft 365 Defender & Microsoft Sentinel
```
let SuspiciousTLD = externaldata(TLD: string)[@"https://raw.githubusercontent.com/cyb3rmik3/Hunting-Lists/main/netcraft-tlds.csv"] with (format="csv", ignoreFirstRecord=True);
DeviceNetworkEvents  
| where ActionType == "DnsConnectionInspected"
| extend AdditionalFields = todynamic(AdditionalFields)
| extend DnsQuery = tostring(AdditionalFields.query), ResponseCode = tostring(AdditionalFields.rcode_name), Direction = tostring(AdditionalFields.direction)
| extend TLDArray = split(DnsQuery,'.')
| extend TLD = strcat(".",TLDArray[array_length(TLDArray)-1])
| where Direction == "Out"
| project DeviceName, DnsQuery, ResponseCode, TLDArray, TLD
| join SuspiciousTLD on $left.TLD == $right.TLD
```

### MITRE ATT&CK Mapping
- Tactic: Command and Control
- Technique ID: T1071.004
- [Application Layer Protocol: DNS](https://attack.mitre.org/techniques/T1071/004/)

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 02/09/2023    | Initial publish                   |
