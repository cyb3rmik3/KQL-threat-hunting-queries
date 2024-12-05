# Identify and summarize processor families in your environment

# Description

The following query leverages DeviceTvmHardwareFirmware and will help you build an estate of your environment’s processors which will allow you to identify possibly old and non-reliable devices in your organization.

DeviceTvmHardwareFirmware 

### Microsoft Defender XDR
```
DeviceTvmHardwareFirmware 
| where ComponentType == @"Processor"
| project ProcFamily = parse_json(AdditionalFields)["Family"]
| summarize count() by tostring(ProcFamily)
| sort by ProcFamily asc 
```

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 05/12/2024    | Initial publish                        |
