# Identification of risky users risk dismissal or account compromised confirmation

## Description

The following query will identify through Microsoft Entra ID Protection capacity, risky users operations that include risk dismissal or account compromised confirmation.

### Microsoft Sentinel
```
let Timeframe = 90d;
AuditLogs
    | where TimeGenerated > ago(Timeframe)
    // Choose whether you want to focus on DissmissUser or ConfirmAccountCompromised operations
    //| where OperationName == "DismissUser"
    //| where OperationName == "ConfirmAccountCompromised"
    | extend SuspUser = tostring(TargetResources[0].displayName)
    // Add here the name of the user you want to focus on
    //| where SuspUser contains @""
    | extend SecUser = InitiatedBy.user.userPrincipalName
    // Add here the name of the security operator that confirmed account compromized
    //| where SecUser contains @""
    | project TimeGenerated, SuspUser, SecUser
    | sort by TimeGenerated desc
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 14/12/2023    | Initial publish                        |
