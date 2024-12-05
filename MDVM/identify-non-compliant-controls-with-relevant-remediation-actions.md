# Identify non-compliant controls with relevant remediation actions

# Description

The following query leverages DeviceBaselineComplianceAssessment and DeviceBaselineComplianceAssessmentKB. You may choose a baseline assessment profile and then focus on controls that have been found not to be compliant with their relevant remediation options.

### Microsoft Defender XDR
```
let Profile = ""; // Insert ProfileId here
DeviceBaselineComplianceAssessment
| where ProfileId == Profile 
| where IsCompliant == "0"
| where IsExempt == "0"
| join kind=inner (
    DeviceBaselineComplianceAssessmentKB
) on ConfigurationId
| summarize by ConfigurationId, ConfigurationName, ConfigurationDescription, ConfigurationCategory, RemediationOptions, ConfigurationBenchmark
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 05/12/2024    | Initial publish                        |
