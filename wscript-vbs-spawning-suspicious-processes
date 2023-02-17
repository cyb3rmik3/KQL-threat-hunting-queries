// Security Center WScript VBS file spawning suspicious processes detection query | GULOADER
DeviceProcessEvents
| where InitiatingProcessParentFileName contains @"wscript.exe"
| where InitiatingProcessCommandLine contains ".vbs"
| where InitiatingProcessFileName has_any (@"powershell.exe", @"pwsh.exe", @"cmd.exe")

// Source: https://www.virustotal.com/gui/file/dc0b4a1c978fee4d876b50912477445498b44b9f10efdd0f43eae64612f90c0a
// Source: https://www.virustotal.com/gui/file/5b5eda30397c73f6f55070507ec1a745b161ebbfdab09ab340c0ad7583c59c90
