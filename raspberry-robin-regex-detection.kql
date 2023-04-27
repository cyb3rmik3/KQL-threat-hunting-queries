# Detect RaspBerry Robin through msiexec and regex on http call

## Query Information

### Description

A detection opportunity by taking into consideration the fact that RaspBerry Robin domains used have the following structure:
```
http://xx.xx:8080/xx/hostname?username
```
The query also incorporates the 

### References
- https://redcanary.com/blog/raspberry-robin/

### Microsoft 365 Defender
```
let RaspBerryRobin = @'[A-Za-z0-9]+://[A-Za-z0-9]+\.[A-Za-z0-9]+:8080/[A-Za-z0-9]+/[A-Za-z0-9]+\?[A-Za-z0-9]+';
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName has @'cmd.exe'
| where ProcessCommandLine has "msiexec"
| where ProcessCommandLine matches regex RaspBerryRobin
| project Timestamp, DeviceName, AccountName, FileName, InitiatingProcessFileName, ProcessCommandLine
```
