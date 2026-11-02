```
// ================================================
// TIFCE Pillar 4: Feed Freshness
//
// Purpose:
// - Measure how recently each feed added or updated IOCs.
// - Blend recency and IOC addition velocity into a freshness score.
// ================================================
let FreshnessLookback = 30d;
// Indicator versions older than this are ignored; align it with the table's retention
let TILookback = 90d;
let CanonicalIOC = (iocType:string, iocValue:string) {
    strcat(tolower(trim(" ", iocType)), ":", tolower(trim(" ", iocValue)))
};
// -----------------------------
// Build per-feed IOC first/last seen state
// -----------------------------
let FeedIOCState =
    ThreatIntelIndicators
    | where TimeGenerated > ago(TILookback)
    // Each update writes a new row; keep only the latest version of each indicator,
    // remembering when its first version was seen
    | summarize arg_max(TimeGenerated, *), FirstVersionTime = min(TimeGenerated) by Id
    | where IsDeleted == false
    | where isnotempty(SourceSystem) and isnotempty(ObservableKey) and isnotempty(ObservableValue)
    | extend TIFeed = tostring(SourceSystem)
    | extend IOCTypeRaw = tostring(split(ObservableKey, ":", 0))
    | extend IOCType = replace_regex(tolower(trim(" ", IOCTypeRaw)), @"[\[\]""']", "")
    | extend IOC = CanonicalIOC(IOCType, tostring(ObservableValue))
    | extend CreatedTime = coalesce(
        todatetime(column_ifexists("Created", datetime(null))),
        FirstVersionTime
      )
    | extend UpdatedTime = coalesce(
        todatetime(column_ifexists("Modified", datetime(null))),
        todatetime(column_ifexists("LastUpdatedTime", datetime(null))),
        CreatedTime,
        TimeGenerated
      )
    | summarize
        FirstSeen = min(CreatedTime),
        LastSeen  = max(UpdatedTime)
      by TIFeed, IOC;
// -----------------------------
// Aggregate freshness metrics per feed
// -----------------------------
FeedIOCState
| extend IOCAgeDays = datetime_diff("day", now(), FirstSeen)
| summarize
    TotalDistinctIOCs   = count(),
    LastNewIOC          = max(FirstSeen),
    LastFeedActivity    = max(LastSeen),
    NewIOCsLast7d       = countif(FirstSeen > ago(7d)),
    NewIOCsLast30d      = countif(FirstSeen > ago(FreshnessLookback)),
    UpdatedIOCsLast7d   = countif(LastSeen > ago(7d)),
    UpdatedIOCsLast30d  = countif(LastSeen > ago(FreshnessLookback)),
    AvgIOCAgeDays       = round(avg(todouble(IOCAgeDays)), 1),
    P50IOCAgeDays       = toint(percentile(IOCAgeDays, 50))
  by TIFeed
| extend
    DaysSinceLastNewIOC   = datetime_diff("day", now(), LastNewIOC),
    DaysSinceLastActivity = datetime_diff("day", now(), LastFeedActivity)
// Recency favors recently active feeds; velocity favors feeds adding many new IOCs.
| extend
    FreshPctRecent = round(
        iif(TotalDistinctIOCs > 0, 100.0 * todouble(NewIOCsLast30d) / todouble(TotalDistinctIOCs), 0.0),
        2
    ),
    RecencyComponent = case(
        DaysSinceLastActivity <= 1, 100.0,
        DaysSinceLastActivity <= 7, 80.0,
        DaysSinceLastActivity <= 30, 50.0,
        DaysSinceLastActivity <= 90, 20.0,
        0.0
    ),
    VelocityComponent = iif(
        TotalDistinctIOCs > 0,
        100.0 * todouble(NewIOCsLast30d) / todouble(TotalDistinctIOCs),
        0.0
    )
// Weighted score emphasizes recency (60%) over velocity (40%).
| extend
    FreshnessScore = round(0.6 * RecencyComponent + 0.4 * VelocityComponent, 2),
    FreshnessStatus = case(
        DaysSinceLastActivity <= 1, "Very Fresh (daily activity)",
        DaysSinceLastActivity <= 7, "Fresh (weekly activity)",
        DaysSinceLastActivity <= 30, "Moderately Fresh",
        "Stale / Inactive (>30 days since activity)"
    )
| order by FreshnessScore desc, DaysSinceLastActivity asc
| project
    Feed = TIFeed,
    TotalDistinctIOCs,
    FreshnessScore,
    NewIOCsLast7d,
    NewIOCsLast30d,
    UpdatedIOCsLast7d,
    UpdatedIOCsLast30d,
    DaysSinceLastNewIOC,
    DaysSinceLastActivity,
    AvgIOCAgeDays,
    P50IOCAgeDays,
    FreshPctRecent,
    LastNewIOC,
    LastFeedActivity,
    FreshnessStatus
```
