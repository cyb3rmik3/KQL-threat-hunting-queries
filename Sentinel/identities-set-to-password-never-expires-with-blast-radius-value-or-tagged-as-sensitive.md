# Identities set to “Password Never Expires” with Blast Radius value or tagged as Sensitive

# Description

The following query will take advantage of the recently introduced IdentityInfo table and will identify enabled accounts that are set with no password expiration that either have a Blast Radius value or are ragged as Sensitive. Results might return accounts that should be further investigated whether the pose a risk or not.

### Defender XDR
```
let IdBlastRadiusLow =
IdentityInfo
| where IsAccountEnabled == "1"
| where parse_json(UserAccountControl)[1] == 'PasswordNeverExpires'
| where BlastRadius == "Low"
| extend BlastRadius = "🟨 Low"
| project AccountDisplayName, AccountName, EmailAddress, BlastRadius;
let IdBlastRadiusMedium =
IdentityInfo
| where IsAccountEnabled == "1"
| where parse_json(UserAccountControl)[1] == 'PasswordNeverExpires'
| where BlastRadius == "Medium"
| extend BlastRadius = "🟧 Medium"
| project AccountDisplayName, AccountName, EmailAddress, BlastRadius;
let IdBlastRadiusHigh =
IdentityInfo
| where IsAccountEnabled == "1"
| where parse_json(UserAccountControl)[1] == 'PasswordNeverExpires'
| where BlastRadius == "High"
| extend BlastRadius = "🟥 High"
| project AccountDisplayName, AccountName, EmailAddress, BlastRadius;
let SensitiveAccount =
IdentityInfo
| where IsAccountEnabled == "1"
| where parse_json(UserAccountControl)[1] == 'PasswordNeverExpires'
| where Tags != "[]"
| extend Tags = "⚠️ Sensitive Account"
| project AccountDisplayName, AccountName, EmailAddress, Tags;
union isfuzzy=true IdBlastRadiusLow,IdBlastRadiusMedium, IdBlastRadiusHigh, SensitiveAccount
| summarize by AccountDisplayName, AccountName, EmailAddress, BlastRadius, Tags
| sort by AccountDisplayName asc 
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 16/05/2025    | Initial publish                        |
