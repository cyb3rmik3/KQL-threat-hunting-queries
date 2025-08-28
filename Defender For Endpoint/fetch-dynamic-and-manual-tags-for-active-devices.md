# Fetch dynamic and manual tags for active devices

### Description

This query takes into account the DeviceInfo table and will provide the devices based on OSPlatform value (Windows10, Windows11 etc) and what you consider as an inactive device (last seen 7 days for example) and will identify for each device its tags, whether dynamic or manual.

### References
- https://techcommunity.microsoft.com/discussions/microsoftdefenderatp/how-to-fetch-dynamic-tags-in-defender-for-endpoint-machines-api-or-kql/4440925
- 
### Microsoft Defender XDR
```
// Define which devices are of interest based on OSPlatform value
let OS = dynamic(["Windows10","Windows11"]);
// Set the threshold for what counts as an active device
// Devices not seen in the last 7 days (or choose otherwise) will be excluded
let ActiveThresholdDays = 7;
DeviceInfo
| where OSPlatform has_any (OS)
| extend LastSeen = Timestamp
// Normalize the dynamic and manual tags columns
| extend DynamicTagsArray = iif(isnull(DeviceDynamicTags), 
    dynamic([]), todynamic(DeviceDynamicTags))
| extend ManualTagsArray  = iif(isnull(DeviceManualTags),  
    dynamic([]), todynamic(DeviceManualTags))
// Combine both manual and dynamic tags into a single array per device
| extend AllTags = array_concat(DynamicTagsArray, ManualTagsArray)
// Exclude devices with no tags
| where array_length(AllTags) > 0  
| mv-expand Tag=AllTags
| extend Tag = tostring(Tag)
| extend DaysSinceLastSeen = datetime_diff("day", now(), LastSeen)
| where DaysSinceLastSeen <= ActiveThresholdDays
| summarize HasTag=any(true) by DeviceName, Tag
// Replace the boolean flag (1) with an emoji for readability in the results
// If the device has tag, mark with ✅, otherwise leave blank
| extend HasTagMark = iif(HasTag == true, "✅", "")
| evaluate pivot(Tag, any(HasTagMark), DeviceName)
```

### Versioning
| Version       | Date          | Comments                          |
| ------------- |---------------| ----------------------------------|
| 1.0           | 28/08/2025    | Initial publish                   |
