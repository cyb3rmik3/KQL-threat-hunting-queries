```
// ================================================
// TIFCE Pillar 2: Environmental Relevance
// Query 1: XDR Device + Email + Entra ID telemetry
//
// Purpose:
// - Identify whether active TI IOCs are found in XDR telemetry.
//
// Supports:
// - file
// - ipv4-addr
// - ipv6-addr
// - network-traffic
// - domain-name
// - url
// - email-addr
//
// Matching:
// - Only the latest version of each indicator is evaluated
// - File IOCs match SHA256, SHA1 or MD5
// - URLs are compared without scheme and trailing slash
// - A domain IOC also matches its subdomains (evil.com matches a.evil.com)
//
// No observe / block / deny / disposition logic
// ================================================
// Indicator versions older than this are ignored; align it with the table's retention
let TILookback = 90d;
// Telemetry window when run standalone; the workbook uses its Time Range picker
let TelemetryStart = ago(30d);
let TelemetryEnd = now();
let CanonicalIOC = (iocType:string, iocValue:string) {
    let t = tolower(trim(" ", iocType));
    let v = tolower(trim(" ", iocValue));
    strcat(t, ":", iff(t == "url", trim_end("/", replace_regex(v, @"^[a-z][a-z0-9+.-]*://", "")), v))
};
// MDE often logs RemoteUrl as a bare host, which parse_url cannot read without a scheme
let UrlHost = (url:string) {
    let u = trim(" ", url);
    tostring(parse_url(iff(u contains "://", u, strcat("http://", u))).Host)
};
// IPv4-mapped IPv6 (::ffff:1.2.3.4) is reduced to plain IPv4
let NormalizeIP = (ip:string) {
    replace_regex(tolower(trim(" ", ip)), @"^::ffff:(\d+\.\d+\.\d+\.\d+)$", @"\1")
};
// A domain plus its parent domains, so a.b.evil.com also counts as b.evil.com and evil.com
let DomainAndParents = (domain:string) {
    let d = tolower(trim(" ", domain));
    let labels = split(d, ".");
    let n = array_length(labels);
    set_difference(pack_array(
        d,
        iff(n > 2, strcat_array(array_slice(labels, -2, -1), "."), d),
        iff(n > 3, strcat_array(array_slice(labels, -3, -1), "."), d),
        iff(n > 4, strcat_array(array_slice(labels, -4, -1), "."), d),
        iff(n > 5, strcat_array(array_slice(labels, -5, -1), "."), d),
        iff(n > 6, strcat_array(array_slice(labels, -6, -1), "."), d)
    ), dynamic([]))
};
// -----------------------------
// Active TI indicators
// -----------------------------
let ActiveIOCs =
    ThreatIntelIndicators
    | where TimeGenerated > ago(TILookback)
    // Each update writes a new row; keep only the latest version of each indicator
    | summarize arg_max(TimeGenerated, IsActive, IsDeleted, ValidUntil, SourceSystem, ObservableKey, ObservableValue) by Id
    | where IsActive == true
      and IsDeleted == false
      and (isnull(ValidUntil) or ValidUntil > now())
    | where isnotempty(SourceSystem)
      and isnotempty(ObservableKey)
      and isnotempty(ObservableValue)
    | extend TIFeed = tostring(SourceSystem)
    | extend IOCType = tolower(trim(" ", tostring(split(ObservableKey, ":")[0])))
    | where IOCType in (
        "file",
        "ipv4-addr",
        "ipv6-addr",
        "network-traffic",
        "domain-name",
        "url",
        "email-addr"
    )
    | extend IOC = CanonicalIOC(IOCType, tostring(ObservableValue))
    | summarize by TIFeed, IOC;
// -----------------------------
// IOC matches in XDR telemetry
// Each source is deduplicated first, then emits (IOCType, IOCValue) observations
// -----------------------------
let TelemetryIOCs =
    union isfuzzy=true
    // Device file hashes
    (
        DeviceFileEvents
        | where TimeGenerated between (TelemetryStart .. TelemetryEnd)
        | summarize Hits = count() by SHA256, SHA1, MD5 = tostring(column_ifexists("MD5", ""))
        | mv-expand IOCValue = pack_array(SHA256, SHA1, MD5) to typeof(string)
        | project IOCType = "file", IOCValue, Hits, TelemetrySource = "DeviceFileEvents"
    ),
    // Executed process hashes
    (
        DeviceProcessEvents
        | where TimeGenerated between (TelemetryStart .. TelemetryEnd)
        | summarize Hits = count() by SHA256, SHA1, MD5 = tostring(column_ifexists("MD5", ""))
        | mv-expand IOCValue = pack_array(SHA256, SHA1, MD5) to typeof(string)
        | project IOCType = "file", IOCValue, Hits, TelemetrySource = "DeviceProcessEvents"
    ),
    // Device network IPs, IPv6, network-traffic, URLs, and domains
    (
        DeviceNetworkEvents
        | where TimeGenerated between (TelemetryStart .. TelemetryEnd)
        | where isnotempty(RemoteIP) or isnotempty(RemoteUrl)
        | summarize Hits = count() by RemoteIP, RemoteUrl
        | extend IP = NormalizeIP(RemoteIP), Host = UrlHost(RemoteUrl)
        | mv-expand Observation = pack_array(
            bag_pack("Type", iff(IP contains ":", "ipv6-addr", "ipv4-addr"), "Value", IP),
            bag_pack("Type", "network-traffic", "Value", IP),
            bag_pack("Type", "url", "Value", RemoteUrl),
            bag_pack("Type", "domain-name", "Value", Host)
        )
        | project IOCType = tostring(Observation.Type), IOCValue = tostring(Observation.Value), Hits, TelemetrySource = "DeviceNetworkEvents"
    ),
    // Email URLs and domains
    (
        EmailUrlInfo
        | where TimeGenerated between (TelemetryStart .. TelemetryEnd)
        | where isnotempty(Url) or isnotempty(UrlDomain)
        | summarize Hits = count() by Url, UrlDomain
        | mv-expand Observation = pack_array(
            bag_pack("Type", "url", "Value", Url),
            bag_pack("Type", "domain-name", "Value", UrlDomain)
        )
        | project IOCType = tostring(Observation.Type), IOCValue = tostring(Observation.Value), Hits, TelemetrySource = "EmailUrlInfo"
    ),
    // Clicked URLs and domains (Safe Links)
    (
        UrlClickEvents
        | where TimeGenerated between (TelemetryStart .. TelemetryEnd)
        | where isnotempty(Url)
        | summarize Hits = count() by Url
        | mv-expand Observation = pack_array(
            bag_pack("Type", "url", "Value", Url),
            bag_pack("Type", "domain-name", "Value", UrlHost(Url))
        )
        | project IOCType = tostring(Observation.Type), IOCValue = tostring(Observation.Value), Hits, TelemetrySource = "UrlClickEvents"
    ),
    // Email attachment hashes
    (
        EmailAttachmentInfo
        | where TimeGenerated between (TelemetryStart .. TelemetryEnd)
        | summarize Hits = count() by SHA256, SHA1 = tostring(column_ifexists("SHA1", ""))
        | mv-expand IOCValue = pack_array(SHA256, SHA1) to typeof(string)
        | project IOCType = "file", IOCValue, Hits, TelemetrySource = "EmailAttachmentInfo"
    ),
    // Email addresses + derived email domains
    (
        EmailEvents
        | where TimeGenerated between (TelemetryStart .. TelemetryEnd)
        | extend EmailCandidates = pack_array(
            tostring(column_ifexists("SenderFromAddress", "")),
            tostring(column_ifexists("SenderMailFromAddress", "")),
            tostring(column_ifexists("RecipientEmailAddress", ""))
        )
        | mv-expand EmailAddress = EmailCandidates to typeof(string)
        | extend EmailAddress = tolower(trim(" ", EmailAddress))
        | where EmailAddress contains "@"
        | summarize Hits = count() by EmailAddress
        | mv-expand Observation = pack_array(
            bag_pack("Type", "email-addr", "Value", EmailAddress),
            bag_pack("Type", "domain-name", "Value", tostring(split(EmailAddress, "@")[1]))
        )
        | project IOCType = tostring(Observation.Type), IOCValue = tostring(Observation.Value), Hits, TelemetrySource = "EmailEvents"
    ),
    // Entra ID sign-in source IPs
    (
        SigninLogs
        | where TimeGenerated between (TelemetryStart .. TelemetryEnd)
        | where isnotempty(IPAddress)
        | summarize Hits = count() by IP = NormalizeIP(IPAddress)
        | mv-expand Observation = pack_array(
            bag_pack("Type", iff(IP contains ":", "ipv6-addr", "ipv4-addr"), "Value", IP),
            bag_pack("Type", "network-traffic", "Value", IP)
        )
        | project IOCType = tostring(Observation.Type), IOCValue = tostring(Observation.Value), Hits, TelemetrySource = "SigninLogs"
    )
    | where isnotempty(IOCValue)
    | mv-expand MatchValue = iff(IOCType == "domain-name", DomainAndParents(IOCValue), pack_array(IOCValue)) to typeof(string)
    | extend IOC = CanonicalIOC(IOCType, MatchValue)
    | summarize by IOC;
// -----------------------------
// Feed-level relevance scoring
// -----------------------------
ActiveIOCs
| join kind=leftouter (
    TelemetryIOCs
    | project TelemetryIOC = IOC
) on $left.IOC == $right.TelemetryIOC
| summarize
    TotalIOCs = count(),
    FoundIOCs = countif(isnotempty(TelemetryIOC)),
    NotFoundIOCs = countif(isempty(TelemetryIOC))
    by TIFeed
| extend
    EnvironmentalRelevanceScore = FoundIOCs,
    RelevancePct = round(
        iif(TotalIOCs > 0, 100.0 * todouble(FoundIOCs) / todouble(TotalIOCs), 0.0),
        2
    ),
    NotFoundPct = round(
        iif(TotalIOCs > 0, 100.0 * todouble(NotFoundIOCs) / todouble(TotalIOCs), 0.0),
        2
    )
| order by EnvironmentalRelevanceScore desc
| project
    Feed = TIFeed,
    TotalIOCs,
    FoundIOCs,
    NotFoundIOCs,
    RelevancePct,
    NotFoundPct,
    EnvironmentalRelevanceScore;
```
