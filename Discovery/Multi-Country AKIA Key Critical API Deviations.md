# Suspicious Spike in Failed AWS API Calls by Non-ASIA Access Key

### Description

This detection first identifies AWS access keys with the AKIA prefix that are used from multiple countries within an 8-hour sliding window over the past 14 days. For these keys, it then performs anomaly detection on critical API calls, detecting statistically significant spikes in failed or unauthorized activity relative to historical behavior. Such patterns may indicate compromised credentials or reconnaissance activity targeting sensitive AWS resources.

### Microsoft Sentinel
```
let CriticalApiCalls = dynamic(["ConsoleLogin", "StartInstances", "CreateAccessKey", "CreateGroup", "CreateUser", "PutGroupPolicy", "AssumeRoleWithWebIdentity", "SendCommand", "CreateLoginProfile", "AttachUserPolicy", "GetSessionToken", "RunInstances", "AuthorizeSecurityGroupIngress", "AddUserToGroup", "StopLogging", "GetSecretValue", "ListUsers", "AssumeRole", "DeleteTrail", "GetPasswordData", "DescribeInstances", "SwitchRole", "DeleteDetector", "CreateSecret", "GetCallerIdentity", "DeactivateMFADevice", "PutSecretValue", "ListBuckets", "CreateSnapshot", "ModifySnapshotAttribute", "PutBucketVersioning", "ModifyDBSnapshotAttribute", "DeleteObject", "GetObject", "DeleteDBInstance", "CopyObject", "DeletePublicAccessBlock", "ListSecrets"]); // List obtained from https://aws.plainenglish.io/aws-cloudtrail-event-cheatsheet-a-detection-engineers-guide-to-critical-api-calls-part-1-04fb1588556f. I added ListSecrets as well
let lookback = 14d;
let cutoff = now();
let lookbackwindow = 8h;
let bintime = 1h;
let AWSNonASIAKeyFilteringFunction = view () {
    AWSCloudTrail
    | where EventName in (CriticalApiCalls)
    | where isnotempty(UserIdentityAccessKeyId)
    | where isnotempty(UserIdentityArn)
    | extend AccessKeyIDPrefix = tostring(extract(@"^([A-Z]{4})", 1, UserIdentityAccessKeyId))
    | where AccessKeyIDPrefix == "AKIA"
    | extend
        CountryGeoIP = tostring(geo_info_from_ip_address(SourceIpAddress).country),
        SeriesID = hash_many(UserIdentityArn, UserIdentityAccessKeyId)
    | project
        TimeGenerated,
        EventName,
        ErrorCode,
        UserIdentityArn,
        UserIdentityAccessKeyId,
        SourceIpAddress,
        CountryGeoIP,
        SeriesID,
        UserAgent
};
let MultipleCoutryConnections = materialize (AWSNonASIAKeyFilteringFunction
    | where TimeGenerated between (ago(lookback) .. cutoff)
    | where isnotempty(CountryGeoIP)
    | evaluate sliding_window_counts(CountryGeoIP, TimeGenerated, ago(lookback), cutoff, lookbackwindow, bintime, SeriesID)
    | extend ConnectedFromMoreThanOneCountry = iff(Dcount > 1, true, false)
    | where ConnectedFromMoreThanOneCountry
    | summarize make_set(SeriesID));
AWSNonASIAKeyFilteringFunction
| where TimeGenerated between (ago(lookback) .. cutoff)
| make-series
    SuccessfulEventCount = countif(isempty(ErrorCode)),
    UnauthorizedEventCount = countif(ErrorCode in ("AccessDenied", "Client.UnauthorizedOperation")),
    DistinctSuccessfulEvents = count_distinctif(EventName, isempty(ErrorCode)),
    DistinctUnauthorizedEvents = count_distinctif(EventName, (ErrorCode in ("AccessDenied", "Client.UnauthorizedOperation")))
    on TimeGenerated
    from ago(lookback) to cutoff step bintime
    by SeriesID
| extend
    TotalUnauthorizedEventsOutliers = series_outliers(UnauthorizedEventCount, "tukey", 1.0),
    DistinctUnauthorizedEventsStats = series_stats_dynamic(DistinctUnauthorizedEvents)
| extend
    MinUnauthorized = toreal(DistinctUnauthorizedEventsStats.min),
    MaxUnauthorized = toreal(DistinctUnauthorizedEventsStats.max),
    AverageUnauthorized = toreal(DistinctUnauthorizedEventsStats.avg),
    StandardDeviationUnauthorized = toreal(DistinctUnauthorizedEventsStats.stdev),
    VarianceUnauthorized = toreal(DistinctUnauthorizedEventsStats.variance)
| mv-expand
    TimeGenerated to typeof(datetime),
    SuccessfulEventCount to typeof (int),
    UnauthorizedEventCount to typeof (int),
    DistinctSuccessfulEvents to typeof (int),
    DistinctUnauthorizedEvents to typeof (int),
    TotalUnauthorizedEventsOutliers to typeof (real)
| where TotalUnauthorizedEventsOutliers > 1
| where DistinctUnauthorizedEvents > 0
| where DistinctUnauthorizedEvents >= DistinctSuccessfulEvents
| where VarianceUnauthorized < 0.05
| where MaxUnauthorized >= MinUnauthorized + 2
| extend ZScore = (DistinctUnauthorizedEvents - AverageUnauthorized) / StandardDeviationUnauthorized
| where ZScore > 2
| project-away DistinctUnauthorizedEventsStats
| where SeriesID in (MultipleCoutryConnections)
| extend
    BackwardsTimeWindow = TimeGenerated - bintime,
    ForwardTimeWindow = TimeGenerated + bintime
| join kind=inner (AWSNonASIAKeyFilteringFunction
    | where TimeGenerated between (ago(lookback) .. cutoff)
    | where SeriesID in (MultipleCoutryConnections)
    | summarize
        DistinctSuccessfulEventSet = make_set_if(EventName, isempty(ErrorCode)),
        DistinctUnauthorizedEventSet = make_set_if(EventName, (ErrorCode in ("AccessDenied", "Client.UnauthorizedOperation"))),
        UserIdentityARNs = make_set(UserIdentityArn),
        AccessKeyIDs = make_set(UserIdentityAccessKeyId)
        by bin(TimeGenerated, bintime), SeriesID
    | extend
        DistinctSuccessfulEventSetCount = array_length(DistinctSuccessfulEventSet),
        DistinctUnauthorizedEventSetCount = array_length(DistinctUnauthorizedEventSet),
        UserIdentityARNandKeyID = set_union(UserIdentityARNs, AccessKeyIDs)
    | where DistinctUnauthorizedEventSetCount > 0)
    on SeriesID
| where TimeGenerated1 between (BackwardsTimeWindow .. ForwardTimeWindow)
| where DistinctSuccessfulEventSetCount >= DistinctSuccessfulEvents
| where DistinctUnauthorizedEventSetCount >= DistinctUnauthorizedEvents
| project
    TimeGenerated,
    UserIdentityARNandKeyID,
    DistinctSuccessfulEventSet,
    DistinctUnauthorizedEventSet,
    DistinctUnauthorizedEventSetCount,
    DistinctSuccessfulEventSetCount,
    TotalUnauthorizedEventsOutliers,
    AverageUnauthorized,
    StandardDeviationUnauthorized,
    VarianceUnauthorized,
    ZScore
| where TimeGenerated between (ago(bintime) .. cutoff)
```

### MITRE ATT&CK Mapping
- Tactics: Discovery
- Technique ID: T1087.004
- [Account Discovery: Cloud Account](https://attack.mitre.org/techniques/T1087/004/)

- Tactics: Discovery
- Technique ID: T1580
- [Cloud Infrastructure Discovery](https://attack.mitre.org/techniques/T1580/)

- Tactics: Execution
- Technique ID: T1059.009
- [Command and Scripting Interpreter: Cloud API](https://attack.mitre.org/techniques/T1059/009/)

### Versioning
| Version       | Date          | Comments                               |
| ------------- |---------------| ---------------------------------------|
| 1.0           | 23/09/2025    | Initial publish                        |