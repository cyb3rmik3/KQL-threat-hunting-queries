# Identify Log Analytics Contributor and Data Purger role assignment

# Description

The following query, will allow you to identify if the roles Log Analytics Contributor and Data Purger have been enabled in your log analytics workspace resource group. This would be quite alarming, as it would mean that the users with the specific Azure Role, would be able to purge data in your Sentinel’s log analytics workspace.

### Microsoft Sentinel
```
let AzRoleID = dynamic(["92aaf0da-9dab-42b6-94a3-d43ce8d16293", "150f5e0c-0603-4f03-8c7f-cf70034c4e90"]); // Log Analytics Contributor & Data Purger Azure Role IDs
let LAWResourceGroup = "<your log analytics workspace resource group here>"; // Define Resource Group containing Sentinel's LAW
AzureActivity
| where ResourceGroup == LAWResourceGroup
| extend EventSubmissionTimeStamp = tostring(parse_json(Properties).eventSubmissionTimestamp)
| extend EventCaller = tostring(parse_json(Properties).caller)
| extend EventCallerIPAddress = tostring(parse_json(tostring(parse_json(Properties).httpRequest)).clientIpAddress)
| extend EventMessage = tostring(parse_json(Properties).message)
| extend EventRoleDefinitionId = tostring(parse_json(tostring(parse_json(tostring(parse_json(Properties).requestbody)).Properties)).RoleDefinitionId)
| where EventRoleDefinitionId has_any (AzRoleID)
| extend RoleName = case(
    EventRoleDefinitionId endswith "92aaf0da-9dab-42b6-94a3-d43ce8d16293", "Log Analytics Contributor",
    EventRoleDefinitionId endswith "150f5e0c-0603-4f03-8c7f-cf70034c4e90", "Data Purger",
    "Other")
| project EventSubmissionTimeStamp, EventCaller, EventCallerIPAddress, EventMessage, EventRoleDefinitionId, RoleName
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 30/06/2025    | Initial publish                        |
