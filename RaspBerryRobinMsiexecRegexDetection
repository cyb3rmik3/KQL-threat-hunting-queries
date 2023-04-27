# Detect RaspBerry Robin cmd through msiexec and regex on http request call

## Query Information

### Description

A detection opportunity by taking into consideration the fact that RaspBerry Robin domains used have the following structure:
```
http://xx.xx:8080/xx/hostname?username
http://xx.xx:8080/xx/hostname=username
http://xx.xx:8080/xx/hostname
```
The query also incorporates the fact that the parent process is a command prompt and 

### References
- https://redcanary.com/blog/raspberry-robin/
- https://www.trendmicro.com/en_us/research/22/l/raspberry-robin-malware-targets-telecom-governments.html

### Microsoft 365 Defender
```
let rbr01 = @'[A-Za-z0-9]+://[A-Za-z0-9]+\.[A-Za-z0-9]+:8080/[A-Za-z0-9]+/[A-Za-z0-9]+\?[A-Za-z0-9]+';
let rbr02 = @'[A-Za-z0-9]+://[A-Za-z0-9]+\.[A-Za-z0-9]+:8080/[A-Za-z0-9]+/[A-Za-z0-9]+\=[A-Za-z0-9]+';
let rbr03 = @'[A-Za-z0-9]+://[A-Za-z0-9]+\.[A-Za-z0-9]+:8080/[A-Za-z0-9]+/[A-Za-z0-9]+';
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName has @'cmd.exe'
| where ProcessCommandLine has "msiexec"
| where ProcessCommandLine matches regex rbr01 or ProcessCommandLine matches regex rbr02 or ProcessCommandLine matches regex rbr03 
| project Timestamp, DeviceName, AccountName, FileName, InitiatingProcessFileName, ProcessCommandLine
```
