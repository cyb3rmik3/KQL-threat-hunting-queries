# Identify activities in log analytics workspace resource locks

# Description

The following query which would identify activities related to your log analytics workspace relevant resource group locks. That way if someone decides to either edit or delete your lock, you would be able to detect it.

### Microsoft Sentinel
```
let LAWResourceGroup = @"<your log analytics workspace resource group here>"; // Define Resource Group containing Sentinel's LAW
AzureActivity
| where ResourceGroup == LAWResourceGroup
| where OperationNameValue startswith "MICROSOFT.AUTHORIZATION/LOCKS"
| where ActivityStatusValue == "Success"
| extend EventSubmissionTimeStamp = tostring(parse_json(Properties).eventSubmissionTimestamp)
| extend EventCaller = tostring(parse_json(Properties).caller)
| extend EventCallerIPAddress = tostring(parse_json(tostring(parse_json(Properties).httpRequest)).clientIpAddress)
| extend EventMessage = tostring(parse_json(Properties).message)
| extend LocksAction = extract(@"Microsoft\.Authorization\/locks\/(\w+)", 1, EventMessage)
| extend EventRoleDefinitionId = tostring(parse_json(tostring(parse_json(tostring(parse_json(Properties).requestbody)).Properties)).RoleDefinitionId)
| project EventSubmissionTimeStamp, EventCaller, EventCallerIPAddress, LocksAction
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 30/06/2025    | Initial publish                        |
