# Check if Defender EASM IPs or Hosts are mentioned in DDosia Project current configuration

## Description

The following query will check the DDoSia latest configuration to match IPs and Domains that are part of organization's Defender EASM. As a prerequisite, Defender EASM connector should be enabled in Microsoft Sentinel.

### References
- https://witha.name/

### Microsoft Sentinel
```
let DDosiaIntelligence = externaldata(host: string, ip: string)[@"https://witha.name/data/last.csv"] 
    with (format="csv", ignoreFirstRecord=True);
let ddosia_data = DDosiaIntelligence
    | summarize by host, ip
    | extend ddosia_clean_host = replace(@"^www\.", "", host) // Remove www. to match EASM Domain_s
    | project-rename ddosia_host=ddosia_clean_host, ddosia_ip=ip;
// Check if there is an IP match
let ip_query = ddosia_data
| join kind=inner (
    EasmHostAsset_CL 
    | extend individual_ip = parse_json(IpAddresses_s)
    | mv-expand individual_ip // Expand all available IPs related to a Domain in EASM
    | extend IpAddresses_s_ = tostring(individual_ip)
    | project TimeGenerated, IpAddresses_s_
) 
on $left.ddosia_ip == $right.IpAddresses_s_;
// Check if there is a Host/Domain match
let host_query = ddosia_data
| join kind=inner (
    EasmHostAsset_CL 
    | extend asset_host = tostring(parse_json(Domain_s))
    | project TimeGenerated, asset_host
)
on $left.ddosia_host == $right.asset_host;
// Combine all results using the union operator
ip_query
| union host_query
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 09/04/2025    | Initial publish                        |
