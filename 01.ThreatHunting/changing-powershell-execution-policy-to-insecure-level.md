# Changing PowerShell execution policy to insecure level

### Description

PowerShell's execution policy is a safety feature that controls the conditions under which PowerShell loads configuration files and runs scripts. This query will help you identify execution policy changes. Also, you may fine tune the query by excluding InitiatingProcessFileName and InitiatingProcessParentFileName from your environment's applications. 

### References

- https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.4
- https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_powershell_set_policies_to_unsecure_level/

### Microsoft XDR
```
let Timeframe = 7d; // Choose the best timeframe for your investigation
let cmdlet = dynamic([@'-executionpolicy ', @' -ep ', @' -exec ']); 
let parameters = dynamic([@'Bypass ', @'Unrestricted']); 
let exinitapps = datatable(excludedinitapps :string)  // Add as many initiating process filenames you would like to exclude
 ["applicationfilename1.exe",
  "applicationfilename2.exe",
  "applicationfilename3.exe"];
  let exparinitapps = datatable(excludedparinitapps :string)  // Add as many initiating parent process filenames you would like to exclude
 ["applicationfilename1.exe",
  "applicationfilename2.exe",
  "applicationfilename3.exe"];
DeviceProcessEvents
    | where Timestamp > ago(Timeframe)
    | where ProcessCommandLine has_any(cmdlet) and ProcessCommandLine has_any(parameters)
    | where not(InitiatingProcessFileName in (['exinitapps']))
    | where not(InitiatingProcessParentFileName in (['exparinitapps']))
    | sort by Timestamp desc 
```

### MITRE ATT&CK Mapping
- Tactic: Execution
- Technique ID: T1059.001
- [Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/)

### Source

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 24/12/2023    | Initial publish                   |
