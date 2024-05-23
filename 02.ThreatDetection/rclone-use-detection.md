# Rclone use detection

## Description

The following query will detect execution of the Rclone command-line program.

### References
- https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/ransomware-data-exfiltration
- https://research.nccgroup.com/2021/05/27/detecting-rclone-an-effective-tool-for-exfiltration/

### Microsoft Defender XDR
```
let Timeframe = 2d; // Choose the best timeframe for your investigation
DeviceProcessEvents
    | where TimeGenerated > ago(Timeframe)
    | where ProcessVersionInfoProductName has "Rclone"
    | where ProcessCommandLine contains @"rclone" or ProcessCommandLine contains @"--Launch"
    | project TimeGenerated, DeviceName, FolderPath, FileName, ProcessCommandLine, ProcessCreationTime, AccountName, AccountUpn
    | sort by TimeGenerated desc 
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 23/05/2024    | Initial publish                        |
