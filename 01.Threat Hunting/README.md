# Queries MITRE ATT&CK Mapping

I try to map threat hunting queries on MITRE ATT&CK framework and hence, as soon as a query is added it will be also be indexed below per Tactic and a heat map over covered techniques and sub-techniques will be also be maintained.

#### Navigation
- Queries mapped on MITRE ATT&CK
- Queries not mapped on MITRE ATT&CK
- Queries Heatmap

## Queries mapped on MITRE ATT&CK

### Execution

| Title        | Technique ID           | Date added  | Last update |
|---------------|---------------|-------|-------|
| [WScript to VBS file invoking PowerShell](https://github.com/cyb3rmik3/KQL-threat-hunting-queries/blob/main/01.%20Threat%20Hunting/wscript-vbs-spawning-suspicious-processes.md)      | T1059.001 | 17/02/2023 | 20/05/2023 |
| [Endpoints accessing .zip or .mov websites](https://github.com/cyb3rmik3/KQL-threat-hunting-queries/blob/main/01.%20Threat%20Hunting/network-zipandmov-access.md)      | T1204.001 | 14/05/2023 | 16/05/2023 |
| [MOVEit exploit hunting](https://github.com/cyb3rmik3/KQL-threat-hunting-queries/blob/main/01.%20Threat%20Hunting/MOVEit-exploit-hunting.md)      | T1623 | 09/06/2023 | 09/06/2023 |



### Privilege escalation

| Title        | Technique ID           | Date added  | Last update |
|---------------|---------------|-------|-------|
| [OneNote spawning suspicious processes](https://github.com/cyb3rmik3/KQL-threat-hunting-queries/blob/main/01.%20Threat%20Hunting/wscript-vbs-spawning-suspicious-processes.md)      | T1055.012 | 08/02/2023 | 23/05/2023 |
| [Screensaver file invoking internet access](https://github.com/cyb3rmik3/KQL-threat-hunting-queries/blob/main/01.%20Threat%20Hunting/screensaver-file-invoking-internet-access.md)      | T1546.002 | 08/11/2022 | 23/05/2023 |
| [Screensaver file invoking suspicious processes](https://github.com/cyb3rmik3/KQL-threat-hunting-queries/blob/main/01.%20Threat%20Hunting/screensaver-file-invoking-suspicious-processes.md)      | T1623 | 08/11/2022 | 23/05/2023 |

### Discovery

| Title        | Technique ID           | Date added  | Last update |
|---------------|---------------|-------|-------|
| [Remcos RAT checking for geolocation through web](https://github.com/cyb3rmik3/KQL-threat-hunting-queries/blob/main/01.%20Threat%20Hunting/remcos-rat-checking-for-geolocation.md)      | T1614 | 08/06/2023 | 08/06/2023 |

## Queries not mapped on MITRE ATT&CK
None.

## Queries Heatmap

<img src="https://raw.githubusercontent.com/cyb3rmik3/KQL-threat-hunting-queries/efd4043bdfd88871341f9c161668049ecd786c4c/01.%20Threat%20Hunting/attackmapping_20230523.svg">

Updated: 09/06/2023
