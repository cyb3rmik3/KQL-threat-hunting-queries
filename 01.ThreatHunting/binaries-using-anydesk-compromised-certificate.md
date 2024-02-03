# Binaries using AnyDesk Compromised Certificate 

### Description

The following query will hunt for binaries not related to AnyDesk, signed with a potentially compromised signing certificate of AnyDesk.

### References
- https://www.bleepingcomputer.com/news/security/anydesk-says-hackers-breached-its-production-servers-reset-passwords/
- https://github.com/Neo23x0/signature-base/blob/master/yara/gen_anydesk_compromised_cert_feb23.yar

### Microsoft Defender XDR
```
let Timeframe = 7d; // Choose the best timeframe for your investigation
let SuspiciousAnydeskFileCertificate = DeviceFileCertificateInfo
    | where Timestamp > ago(Timeframe)
    | where CertificateSerialNumber =~ "0dbf152deaf0b981a8a938d53f769db8" // Compromised Certificate Serial Number
    | where Issuer == "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"
    | project Timestamp, DeviceName, SHA1;
SuspiciousAnydeskFileCertificate
    | join (DeviceProcessEvents
    | where Timestamp > ago(Timeframe)
    | where ProcessVersionInfoCompanyName !contains @"AnyDesk"
    | project SHA1, ActionType, FileName, FolderPath, ProcessVersionInfoCompanyName, ProcessVersionInfoProductName, ProcessCommandLine, AccountName, InitiatingProcessAccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
    )on SHA1
    | sort by Timestamp desc
```

### MITRE ATT&CK Mapping
- Tactic: Credentials Access
- Technique ID: T1649
- [Steal or Forge Authentication Certificates](https://attack.mitre.org/techniques/T1649/)

### Source

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 03/02/2024    | Initial publish                   |
