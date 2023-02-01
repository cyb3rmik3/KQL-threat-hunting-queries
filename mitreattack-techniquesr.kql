//Identify MITRE ATT&CK Techniques at Microsoft Security Center during the last 30 days and provide results in a piechart
AlertInfo
| where Timestamp > ago(30d)
| where AttackTechniques != ""
| mvexpand todynamic(AttackTechniques)
| summarize count() by tostring(AttackTechniques)
| render piechart 


//Identify MITRE ATT&CK Techniques at Microsoft Sentinel and provide results in a piechart
SecurityAlert
| where isnotempty(Techniques)
| mvexpand todynamic(Techniques) to typeof(string)
| summarize AlertCount = dcount(SystemAlertId) by Techniques
| sort by AlertCount desc
| render piechart 
