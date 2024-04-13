# Minimum characters for PIM activation justification

## Description

The following query will identify PIM activation justification, that don't meet your minimum characters requirement.

### Microsoft Sentinel
```
let CharactersLength = 7; // Choose how many characters would be your mnimum justification
let Timeframe = 90d; // Choose proper timeframe
AuditLogs
    | where TimeGenerated > ago(Timeframe)
    | where OperationName == "Add member to role completed (PIM activation)"
    | where strlen(ResultDescription) < CharactersLength
    | summarize by Identity, ResultDescription
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 13/04/2024    | Initial publish                        |
