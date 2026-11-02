```
// ================================================
// TIFCE Pillar 1: Originality Score (Uniqueness)
// ================================================
// Purpose:
// - Measure how much a feed contributes indicators that are not already
//   broadly present across other feeds.
//
// Scoring logic:
// - Each IOC gets a weight of 1 / FeedCount
// - If only one feed has the IOC, it contributes 1.0 to that feed
// - If 5 feeds share the IOC, it contributes 0.2 to each feed
// - Feeds with more exclusive IOCs get higher originality scores

// Indicator versions older than this are ignored; align it with the table's retention
let TILookback = 90d;
// Step 1: Build a deduplicated set of active IOCs per feed
let ActiveIndicators =
    ThreatIntelIndicators
    | where TimeGenerated > ago(TILookback)
    // Each update writes a new row; keep only the latest version of each indicator
    | summarize arg_max(TimeGenerated, IsActive, IsDeleted, ValidUntil, SourceSystem, ObservableKey, ObservableValue) by Id
    | where IsActive == true
      and IsDeleted == false
      and (isnull(ValidUntil) or ValidUntil > now())
    | where isnotempty(ObservableKey) and isnotempty(ObservableValue)
    | extend
        // Feed identifier used for scoring
        TIFeed = tostring(SourceSystem),
        // Canonical IOC format used consistently across the query
        // Normalization helps avoid mismatches caused by casing or extra spaces
        IOC = strcat(
            tolower(trim(" ", tostring(ObservableKey))),
            ":",
            tolower(trim(" ", tostring(ObservableValue)))
        )
    // Deduplicate so the same feed-IOC pair is only counted once
    | summarize by TIFeed, IOC;
// Step 2: Count how many distinct feeds report each IOC
let IOCFeedCounts =
    ActiveIndicators
    | summarize FeedCount = dcount(TIFeed) by IOC;
// Step 3: Join feed IOCs to IOC distribution and calculate originality
ActiveIndicators
| join kind=inner IOCFeedCounts on IOC
| summarize
    // Sum of fractional IOC contributions for the feed
    OriginalityScore = sum(1.0 / FeedCount),
    // Total distinct IOCs contributed by the feed
    TotalIOCs = count(),
    // Count of IOCs seen only in this single feed
    ExclusiveIOCs = countif(FeedCount == 1)
    by TIFeed
| extend
    // Average originality contribution per IOC
    AvgOriginalityPerIOC = round(OriginalityScore / TotalIOCs, 4),
    // Same idea expressed as a percentage for easier comparison
    OriginalityPct = round(100.0 * OriginalityScore / TotalIOCs, 2)
| order by OriginalityScore desc
| project
    Feed = TIFeed,
    OriginalityScore,
    TotalIOCs,
    AvgOriginalityPerIOC,
    OriginalityPct,
    ExclusiveIOCs
```
