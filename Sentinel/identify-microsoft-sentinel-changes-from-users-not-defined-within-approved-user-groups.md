# Identify Microsoft Sentinel changes from users not defined within approved user groups

# Description

The following query takes into account ExposureGraphEdges, IdentityInfo and SentinelAudit and will allow you to identify if a user outside of the user groups defined to have access to Microsoft Sentinel, made any changes.

### Microsoft Sentinel & Defender XDR
```
let EntraGroups = dynamic(["SentinelAdmins", "XDRAdmins"]); // Define your user groups of interest here
let Timeframe = ago(7d); // Define the required Timeframe
let UserInformation = 
ExposureGraphEdges
| where EdgeLabel == "member of"
| where SourceNodeLabel == "user"
| where not(TargetNodeName has_any (EntraGroups))
| extend EntraGroup = tostring(EntraGroups)
| project SourceNodeName, EntraGroup
| join kind=leftouter IdentityInfo on $left.SourceNodeName == $right.AccountDisplayName  
| summarize by SourceNodeName, EntraGroup, EmailAddress
| project SourceNodeName, EntraGroup, EmailAddress;
SentinelAudit
| where Status == @"Success"
| where TimeGenerated > Timeframe
| extend CallerEmailName = tostring(parse_json(ExtendedProperties)["CallerName"])
| project TimeGenerated, CallerEmailName, OperationName, SentinelResourceName, Description, SentinelResourceType
| join kind=inner UserInformation on $left.CallerEmailName == $right.EmailAddress
| sort by TimeGenerated desc 
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 30/06/2025    | Initial publish                        |
