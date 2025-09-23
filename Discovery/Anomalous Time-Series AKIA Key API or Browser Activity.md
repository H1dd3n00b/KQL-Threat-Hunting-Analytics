# Suspicious Spike in Failed AWS API Calls by Non-ASIA Access Key

### Description

This detection identifies AWS access keys with the AKIA prefix and monitors their activity on critical API calls and across different browsers over the past 14 days. It performs time-series anomaly detection to flag statistically significant spikes in failed or unauthorized API calls, as well as unusual browser usage patterns, relative to historical behavior. Such anomalies may indicate compromised credentials, or reconnaissance activity.

### Microsoft Sentinel
```
let CriticalApiCalls = dynamic(["ConsoleLogin", "StartInstances", "CreateAccessKey", "CreateGroup", "CreateUser", "PutGroupPolicy", "AssumeRoleWithWebIdentity", "SendCommand", "CreateLoginProfile", "AttachUserPolicy", "GetSessionToken", "RunInstances", "AuthorizeSecurityGroupIngress", "AddUserToGroup", "StopLogging", "GetSecretValue", "ListUsers", "AssumeRole", "DeleteTrail", "GetPasswordData", "DescribeInstances", "SwitchRole", "DeleteDetector", "CreateSecret", "GetCallerIdentity", "DeactivateMFADevice", "PutSecretValue", "ListBuckets", "CreateSnapshot", "ModifySnapshotAttribute", "PutBucketVersioning", "ModifyDBSnapshotAttribute", "DeleteObject", "GetObject", "DeleteDBInstance", "CopyObject", "DeletePublicAccessBlock", "ListSecrets"]); // List obtained from https://aws.plainenglish.io/aws-cloudtrail-event-cheatsheet-a-detection-engineers-guide-to-critical-api-calls-part-1-04fb1588556f. I added ListSecrets as well
let lookback = 14d;
let cutoff = now();
let bintime = 1d;
let AWSNonASIAKeyFilteringFunction = view () {
    AWSCloudTrail
    | where EventName in (CriticalApiCalls)
    | where isnotempty(UserIdentityAccessKeyId)
    | where isnotempty(UserIdentityArn)
    | extend AccessKeyIDPrefix = tostring(extract(@"^([A-Z]{4})", 1, UserIdentityAccessKeyId))
    | where AccessKeyIDPrefix == "AKIA"
    | extend
        BrowserUsed = parse_user_agent(UserAgent, "browser")
    | extend Browser = tostring(BrowserUsed.Browser.Family)
    | extend SeriesID = hash_many(UserIdentityArn, UserIdentityAccessKeyId)
    | project
        TimeGenerated,
        EventName,
        ErrorCode,
        UserIdentityArn,
        Browser,
        UserIdentityAccessKeyId,
        SeriesID
};
AWSNonASIAKeyFilteringFunction
| where TimeGenerated between (ago(lookback) .. cutoff)
| make-series
    DistinctSuccessfulEvents = count_distinctif(EventName, isempty(ErrorCode)),
    DistinctUnauthorizedEvents = count_distinctif(EventName, (ErrorCode in ("AccessDenied", "Client.UnauthorizedOperation"))),
    DistinctBrowsers = count_distinct(Browser)
    on TimeGenerated
    from ago(lookback) to cutoff step bintime
    by SeriesID
| extend
    (UnauthorizedEventAnomaly, UnauthorizedEventScore, UnauthorizedEventBaseline) = series_decompose_anomalies(DistinctUnauthorizedEvents, 3.0, -1, "linefit", 1),
    (BrowserAnomaly, BrowserScore, BrowserBaseline) = series_decompose_anomalies(DistinctBrowsers, 3.0, -1, "avg", 1)
| mv-expand
    TimeGenerated to typeof(datetime),
    DistinctSuccessfulEvents to typeof (int),
    DistinctUnauthorizedEvents to typeof (int),
    DistinctBrowsers to typeof (int),
    UnauthorizedEventAnomaly to typeof(int),
    UnauthorizedEventScore to typeof(real),
    UnauthorizedEventBaseline to typeof(real),
    BrowserAnomaly to typeof(int),
    BrowserScore to typeof(real),
    BrowserBaseline to typeof(real)
| where DistinctUnauthorizedEvents >= DistinctSuccessfulEvents
| extend
    AnomalousEvent = iff(UnauthorizedEventAnomaly == 1 and UnauthorizedEventScore / UnauthorizedEventBaseline > 2.5, true, false),
    AnomalousBrowser = iff(BrowserAnomaly == 1 and BrowserScore / BrowserBaseline > 2, true, false)
| where AnomalousEvent or AnomalousBrowser or DistinctUnauthorizedEvents > 0
| extend AnomalyOrigin = case(
                             AnomalousEvent and AnomalousBrowser,
                             "AnomalousBrowserAndAPICall",
                             AnomalousBrowser,
                             "AnomalousBrowser",
                             AnomalousEvent,
                             "AnomalousAPICall",
                             ""
                         )
| where isnotempty(AnomalyOrigin)
| extend
    BackwardsTimeWindow = TimeGenerated - bintime,
    ForwardTimeWindow = TimeGenerated + bintime
| join kind=inner (AWSNonASIAKeyFilteringFunction
    | where TimeGenerated between (ago(lookback) .. cutoff)
    | summarize
        DistinctSuccessfulEventSet = make_set_if(EventName, isempty(ErrorCode)),
        DistinctUnauthorizedEventSet = make_set_if(EventName, (ErrorCode in ("AccessDenied", "Client.UnauthorizedOperation"))),
        DistinctBrowserSet = make_set(Browser),
        UserIdentityARNs = make_set(UserIdentityArn),
        AccessKeyIDs = make_set(UserIdentityAccessKeyId)
        by bin(TimeGenerated, bintime), SeriesID
    | extend
        DistinctBrowserSetCount = array_length(DistinctBrowserSet),
        DistinctSuccessfulEventSetCount = array_length(DistinctSuccessfulEventSet),
        DistinctUnauthorizedEventSetCount = array_length(DistinctUnauthorizedEventSet),
        UserIdentityARNandKeyID = set_union(UserIdentityARNs, AccessKeyIDs))
    on SeriesID
| where TimeGenerated1 between (BackwardsTimeWindow .. ForwardTimeWindow)
| where DistinctSuccessfulEventSetCount >= DistinctSuccessfulEvents
| where DistinctUnauthorizedEventSetCount >= DistinctUnauthorizedEvents
| project
    TimeGenerated,
    UserIdentityARNandKeyID,
    DistinctSuccessfulEventSet,
    DistinctUnauthorizedEventSet,
    DistinctSuccessfulEventSetCount,
    DistinctUnauthorizedEventSetCount,
    DistinctBrowsers,
    DistinctBrowserSet,
    AnomalyOrigin
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