# Queries MITRE ATT&CK Mapping

I try to map threat hunting queries on MITRE ATT&CK framework and hence, as soon as a query is added it will be also be indexed below per Tactic and a heat map over covered techniques and sub-techniques will be also be maintained.

#### Navigation
- Queries mapped on MITRE ATT&CK
- Queries not mapped on MITRE ATT&CK

## Queries mapped on MITRE ATT&CK

### Execution

| Title        | Technique ID           | Date added  | Last update |
|---------------|---------------|-------|-------|
| [WScript to VBS file invoking PowerShell](https://github.com/cyb3rmik3/KQL-threat-hunting-queries/blob/main/01.ThreatHunting/wscript-vbs-spawning-suspicious-processes.md)      | T1059.001 | 17/02/2023 | 20/05/2023 |
| [Endpoints accessing .zip or .mov websites](https://github.com/cyb3rmik3/KQL-threat-hunting-queries/blob/main/01.ThreatHunting/network-zipandmov-access.md)      | T1204.001 | 14/05/2023 | 16/05/2023 |
| [MOVEit exploit hunting](https://github.com/cyb3rmik3/KQL-threat-hunting-queries/blob/main/01.ThreatHunting/MOVEit-exploit-hunting.md)      | T1623 | 09/06/2023 | 09/06/2023 |

### Privilege escalation

| Title        | Technique ID           | Date added  | Last update |
|---------------|---------------|-------|-------|
| [OneNote spawning suspicious processes](https://github.com/cyb3rmik3/KQL-threat-hunting-queries/blob/main/01.ThreatHunting/wscript-vbs-spawning-suspicious-processes.md)      | T1055.012 | 08/02/2023 | 23/05/2023 |
| [Screensaver file invoking internet access](https://github.com/cyb3rmik3/KQL-threat-hunting-queries/blob/main/01.ThreatHunting/screensaver-file-invoking-internet-access.md)      | T1546.002 | 08/11/2022 | 23/05/2023 |
| [Screensaver file invoking suspicious processes](https://github.com/cyb3rmik3/KQL-threat-hunting-queries/blob/main/01.ThreatHunting/screensaver-file-invoking-suspicious-processes.md)      | T1623 | 08/11/2022 | 23/05/2023 |

### Defence evasion

| Title        | Technique ID           | Date added  | Last update |
|---------------|---------------|-------|-------|
| [CVE-2023-36884 Dropped file hunting](https://github.com/cyb3rmik3/KQL-threat-hunting-queries/blob/main/01.ThreatHunting/CVE-2023-36884-dropped-file.md)      | T1211 | 18/07/2023 | 18/07/2023 |

### Discovery

| Title        | Technique ID           | Date added  | Last update |
|---------------|---------------|-------|-------|
| [Remcos RAT checking for geolocation through web](https://github.com/cyb3rmik3/KQL-threat-hunting-queries/blob/main/01.ThreatHunting/remcos-rat-checking-for-geolocation.md)      | T1614 | 08/06/2023 | 08/06/2023 |

### Command and Control

| Title        | Technique ID           | Date added  | Last update |
|---------------|---------------|-------|-------|
| [CVE-2023-36884 URL marker](https://github.com/cyb3rmik3/KQL-threat-hunting-queries/blob/main/01.ThreatHunting/CVE-2023-36884-url-marker.md)      | T1071.001 | 18/07/2023 | 18/07/2023 |

## Queries not mapped on MITRE ATT&CK
None.
