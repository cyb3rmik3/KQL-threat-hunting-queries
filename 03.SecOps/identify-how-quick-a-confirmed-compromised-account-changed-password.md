# Identify how quick a confirmed compromised account changed password

## Description

The following query will identify how much time has occurred since a confirmed compromised account, changed password.

### Microsoft Sentinel
```
// Define the timeframe you would like to look into
let timeframe = 90d;
AuditLogs
    | where TimeGenerated > ago(timeframe)
    | where OperationName == "ConfirmAccountCompromised"
    | extend SuspUser = tostring(TargetResources[0].userPrincipalName)
    | project SuspUser, ConfirmTime=TimeGenerated
| join kind=inner (
    AuditLogs
    | where TimeGenerated > ago(timeframe)
    | where OperationName == "Reset user password" or OperationName == "Reset password (self-service)" or OperationName == "Change user password"
    | where Result == "success"
    | extend SuspUserPw = tostring(TargetResources[0].userPrincipalName)
    | project SuspUserPw, PwChangeTime = TimeGenerated, OperationName
    )
on $left.SuspUser == $right.SuspUserPw
| project SuspUser, ConfirmTime, SuspUserPw, PwChangeTime, OperationName, PwChangeTimeframe = (PwChangeTime - ConfirmTime)
| sort by ConfirmTime desc
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 15/12/2023    | Initial publish                        |
