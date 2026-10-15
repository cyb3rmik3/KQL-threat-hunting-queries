# TIFCE Workbook for Microsoft Sentinel

TIFCE (TI Feed Content Evaluation) is a framework for evaluating the real operational value of threat intelligence feeds in security platforms. Instead of treating all feeds as equally useful, TIFCE measures whether a feed contributes original indicators, appears in your environment, correlates to confirmed malicious activity, and stays current over time.

Framework reference: [TIFCE (TI Feed Content Evaluation)](https://zenodo.org/records/18208974)

This project packages a Microsoft Sentinel workbook and the underlying KQL queries so teams can deploy and review TI feed quality in a repeatable way across environments.

Last update: June 3, 2026 (v1.0)

## Why it matters

Threat intelligence programs often accumulate overlapping feeds with unclear value. That creates operational noise, duplicate indicators, extra cost, and a false sense of coverage. This workbook helps security teams answer practical questions:

- Which feeds add unique intelligence?
- Which feeds are actually relevant to our environment?
- Which feeds correlate to confirmed malicious activity?
- Which feeds are fresh and actively maintained?

Using these measurements, analysts and engineering teams can make better decisions about feed onboarding, retention, tuning, and procurement.

## Who should use this workbook

This workbook is intended for:

- Microsoft Sentinel administrators
- Security operations center analysts
- Threat intelligence teams
- Detection engineers
- Security architects evaluating TI feed quality and overlap

It is especially useful for organizations that ingest multiple TI feeds into Sentinel and want a defensible, evidence-based way to compare them.

## Project structure

- [tifce-workbook.template.json](./tifce-workbook.template.json): ARM template for deploying the shared Sentinel workbook
- [tifce-workbook.parameters.json](./tifce-workbook.parameters.json): Sample ARM parameters file
- [tifce-workbook.json](./tifce-workbook.json): Source workbook JSON used to generate the ARM template
- [tifcepillar1-data.md](./tifcepillar1-data.md): Pillar 1 KQL query for originality scoring
- [tifcepillar2-data.md](./tifcepillar2-data.md): Pillar 2 KQL query for environmental relevance
- [tifcepillar3-data.md](./tifcepillar3-data.md): Pillar 3 KQL query for signal versus noise
- [tifcepillar4-data.md](./tifcepillar4-data.md): Pillar 4 KQL query for feed freshness

## One-click ARM deployment

This project is set up for ARM deployment directly from:

- https://github.com/cyb3rmik3/KQL-threat-hunting-queries/tree/main/TIFCE

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fcyb3rmik3%2FKQL-threat-hunting-queries%2Fmain%2FTIFCE%2Ftifce-workbook.template.json)

During deployment, provide:

- `workspaceResourceId`: The target Log Analytics workspace resource ID used by Microsoft Sentinel
- `workbookDisplayName`: Optional workbook title override
- `workbookId`: Optional workbook GUID if you want a fixed resource name
- `location`: Azure region for the workbook resource

If you prefer deployment by parameters file, update [tifce-workbook.parameters.json](./tifce-workbook.parameters.json) and deploy with ARM, Bicep, Azure CLI, or PowerShell.

## Manual Deployment
- Navigate to Microsoft Sentinel > Workbooks
- Create a new workbook.
- Copy the content of the tifce-workbook.json file in the advanced editor.
- Apply changes.

## Included KQL queries

### Pillar 1: Originality Score

Source: [tifcepillar1-data.md](./tifcepillar1-data.md)

This query measures how much a feed contributes indicators that are not already broadly duplicated across other feeds. Each IOC contribution is weighted by how many feeds contain it, so rare indicators contribute more than common ones.

This helps identify feeds that add genuinely differentiated value.

### Pillar 2: Environmental Relevance

Source: [tifcepillar2-data.md](./tifcepillar2-data.md)

This query checks whether active TI indicators appear in XDR-related telemetry such as file events, network events, email URLs, email attachments, email addresses, and derived email domains.

This helps determine whether a feed is relevant to the organization's actual environment rather than just being large.

### Pillar 3: Signal Versus Noise

Source: [tifcepillar3-data.md](./tifcepillar3-data.md)

This query correlates telemetry-matched IOCs to closed Sentinel incidents and distinguishes indicators associated with `TruePositive` incidents from those associated with other classifications.

This helps assess whether a feed contributes indicators linked to confirmed malicious activity instead of noise or non-malicious detections.

### Pillar 4: Feed Freshness

Source: [tifcepillar4-data.md](./tifcepillar4-data.md)

This query evaluates how recently each feed added or updated indicators and combines recency with IOC addition velocity to produce a freshness score.

This helps identify stale feeds versus feeds that continue to provide current intelligence.

## Limitations

Pillars 2 and 3 rely on table availability and schema compatibility in the connected environment. If one or more tables are missing, results may be partial or empty.

### Pillar 2 table matching scope

- TI source table: `ThreatIntelIndicators`
- Telemetry match tables:
	- `DeviceFileEvents`
	- `DeviceNetworkEvents`
	- `EmailUrlInfo`
	- `EmailAttachmentInfo`
	- `EmailEvents`

### Pillar 3 table matching and correlation scope

- TI source table: `ThreatIntelIndicators`
- Telemetry match tables:
	- `DeviceFileEvents`
	- `DeviceNetworkEvents`
	- `EmailUrlInfo`
	- `EmailAttachmentInfo`
	- `EmailEvents`
- Incident correlation tables:
	- `SecurityIncident`
	- `SecurityAlert`
- Correlation path used:
	- `SecurityIncident.AlertIds` -> `SecurityAlert.SystemAlertId` -> `SecurityAlert.Entities`

## Thank you

Thank you to all early adopters and feedback contributors who helped shape this workbook and validate the TIFCE approach in real Sentinel environments.
- Contributor acknowledgement goes to [xpinux](https://github.com/xpinux/)
- Early adopter and operationalization validation goes to [Sergio Albea](https://github.com/Sergio-Albea), [Bert-JanP](https://github.com/Bert-JanP) & [Uros Babic](https://github.com/uros-babic)

## Feedback and contributions

Feedback is welcome.

- Open a new ticket (Issue) to report bugs, request improvements, or propose feature ideas.
- Push a new branch with your proposed changes and submit it for review.

## Deployment notes

- The workbook is prepared as a shared Sentinel workbook deployed through `Microsoft.Insights/workbooks`.
- Workbook content has been parameterized to avoid hardcoded workspace bindings.
- The workbook uses a workspace selector and time range controls inside the workbook itself.
- Pillar 2 relies on the hunting blade time range rather than a hardcoded telemetry lookback in the query source.

## References

- [TIFCE (TI Feed Content Evaluation)](https://zenodo.org/records/18208974)
- [Microsoft Sentinel](https://learn.microsoft.com/azure/sentinel/)
- [Azure Monitor Workbooks](https://learn.microsoft.com/azure/azure-monitor/visualize/workbooks-overview)
