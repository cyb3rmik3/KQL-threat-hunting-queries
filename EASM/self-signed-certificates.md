# Identify self-signed certificates in EASM

## Description

The following query will identify and present Assets (Domain/Host) in External Attack Surface Management that are associated with self-signed certificates.

### References
- https://securitytrails.com/blog/dangers-of-using-self-signed-certificates

### Microsoft Sentinel
```
EasmRisk_CL 
| where MetricDisplayName_s == "ASI: Self Signed Certificates"
| extend AssetType_Domain = tostring(parse_json(AssetDiscoveryAuditTrail_s)[0].AssetType)
| extend AssetType_Host = tostring(parse_json(AssetDiscoveryAuditTrail_s)[1].AssetType)
| project AssetType_Domain, AssetType_Host, WorkspaceName_s
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 06/10/2024    | Initial publish                        |
