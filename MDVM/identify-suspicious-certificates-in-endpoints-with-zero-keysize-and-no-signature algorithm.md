# Identify suspicious certificates in endpoints with zero keysize and no signature algorithm

## Description

The following query leverages DeviceTvmCertificateInfo table which is available at the MDVM add-on license. Results provided include endpoints with certificates of zero keysize and no signature algorithm. A detected certificate lacks all the fundamental properties needed for secure communication and should be investigated.

### Microsoft Defender XDR
```
let DeviceInformation = DeviceInfo
    | project DeviceId, DeviceName;
DeviceInformation
| join ( DeviceTvmCertificateInfo
    | where KeySize == "0"
    | where SignatureAlgorithm == ""
    | extend TOCN = parse_json(IssuedTo).CommonName
    | extend TOORG = parse_json(IssuedTo).Organization
    | extend TOCountry = parse_json(IssuedTo).CountryName 
    | extend BYCN = parse_json(IssuedBy).CommonName
    | extend BYORG = parse_json(IssuedBy).Organization
    | extend BYCountry = parse_json(IssuedBy).CountryName
    | project DeviceId, Thumbprint, TOCN, TOORG, TOCountry, 
        BYCN, BYORG, BYCountry
) on DeviceId
| project DeviceId, DeviceName, Thumbprint, TOCN,
    TOORG, TOCountry, BYCN, BYORG, BYCountry
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 14/9/2024     | Initial publish                        |
